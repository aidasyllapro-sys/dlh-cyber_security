#!/bin/bash
#
# script name : 14-coverage_assessment.sh
# purpose     : combine the telemetry handoff package (windows_events.json,
#               linux_events.json, attack_ground_truth.json), both
#               detection matrices (windows_detection_matrix.json,
#               linux_detection_matrix.json), both telemetry quality
#               reports (windows_telemetry_quality.json,
#               linux_telemetry_quality.json) and the Sysmon ATT&CK
#               coverage matrix (sysmon_coverage_matrix.json) into a single
#               final assessment: total events by platform/source
#               type/category, detection matrix summary, ATT&CK coverage
#               (covered/partial/blind and the source responsible),
#               known gaps with recommended instrumentation improvements,
#               and a quality summary with a combined handoff confidence
#               rating. Uses jq for all JSON parsing. Writes the result to
#               telemetry_coverage_assessment.json.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
 
# Default resolved paths (built from HANDOFF_DIR below):
#   telemetry_handoff/windows_events.json
#   telemetry_handoff/linux_events.json
#   telemetry_handoff/attack_ground_truth.json
HANDOFF_DIR="telemetry_handoff"
WINDOWS_EVENTS_PATH="${HANDOFF_DIR}/windows_events.json"
LINUX_EVENTS_PATH="${HANDOFF_DIR}/linux_events.json"
GROUND_TRUTH_PATH="${HANDOFF_DIR}/attack_ground_truth.json"
WINDOWS_DETECTION_PATH="windows_detection_matrix.json"
LINUX_DETECTION_PATH="linux_detection_matrix.json"
WINDOWS_QUALITY_PATH="windows_telemetry_quality.json"
LINUX_QUALITY_PATH="linux_telemetry_quality.json"
SYSMON_COVERAGE_PATH="sysmon_coverage_matrix.json"
OUTPUT_PATH="telemetry_coverage_assessment.json"
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to parse and merge JSON from multiple prior tasks. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
echo "[*] Loading telemetry handoff package..."
 
for f in "${WINDOWS_EVENTS_PATH}" "${LINUX_EVENTS_PATH}" "${GROUND_TRUTH_PATH}" \
         "${WINDOWS_DETECTION_PATH}" "${LINUX_DETECTION_PATH}" \
         "${WINDOWS_QUALITY_PATH}" "${LINUX_QUALITY_PATH}" "${SYSMON_COVERAGE_PATH}"; do
    if [[ ! -f "${f}" ]]; then
        echo "Required input file not found: ${f}. Run the earlier tasks (3/7/9/11/10/12/4/8/1) first, or place their output next to this script." >&2
        exit 1
    fi
    if ! jq empty "${f}" >/dev/null 2>&1; then
        echo "File is not valid JSON: ${f}" >&2
        exit 1
    fi
done
 
# ---------------------------------------------------------------------------
# Totals
# ---------------------------------------------------------------------------
windows_event_count="$(jq '.events | length' "${WINDOWS_EVENTS_PATH}")"
linux_event_count="$(jq '.events | length' "${LINUX_EVENTS_PATH}")"
echo "Windows events: ${windows_event_count}"
echo "Linux events: ${linux_event_count}"
 
ground_truth_total="$(jq '.total_actions' "${GROUND_TRUTH_PATH}")"
echo "Ground truth actions: ${ground_truth_total}"
 
# ---------------------------------------------------------------------------
# Detection matrix summary (combined Windows + Linux)
# ---------------------------------------------------------------------------
w_det_total="$(jq '.total_actions' "${WINDOWS_DETECTION_PATH}")"
w_det_captured="$(jq '.captured_actions' "${WINDOWS_DETECTION_PATH}")"
w_det_multi="$(jq '.multi_source_count' "${WINDOWS_DETECTION_PATH}")"
 
l_det_total="$(jq '.total_actions' "${LINUX_DETECTION_PATH}")"
l_det_captured="$(jq '.captured_actions' "${LINUX_DETECTION_PATH}")"
l_det_multi="$(jq '.multi_source_count' "${LINUX_DETECTION_PATH}")"
 
combined_det_total=$((w_det_total + l_det_total))
combined_det_captured=$((w_det_captured + l_det_captured))
combined_det_missed=$((combined_det_total - combined_det_captured))
combined_det_multi=$((w_det_multi + l_det_multi))
 
echo "Detection matrix: ${combined_det_captured}/${combined_det_total} captured"
 
# ---------------------------------------------------------------------------
# ATT&CK coverage
#    NOTE: this reflects sysmon_coverage_matrix.json only (Task 1's
#    Sysmon/Windows ATT&CK mapping) - this module does not produce an
#    equivalent auditd/Linux ATT&CK coverage matrix, so this section is
#    scoped to Windows/Sysmon coverage, not a true cross-platform ATT&CK
#    assessment. That scope limitation is also recorded in the output JSON.
# ---------------------------------------------------------------------------
attack_covered="$(jq '.covered' "${SYSMON_COVERAGE_PATH}")"
attack_partial="$(jq '.partial' "${SYSMON_COVERAGE_PATH}")"
attack_blind="$(jq '.blind' "${SYSMON_COVERAGE_PATH}")"
 
echo "ATT&CK covered: ${attack_covered}"
echo "ATT&CK partial: ${attack_partial}"
echo "ATT&CK blind: ${attack_blind}"
 
# ---------------------------------------------------------------------------
# Quality summary + confidence rating
#    The confidence rating is NOT simply the lower of the two quality
#    scores passed through the good/acceptable/poor thresholds - a known
#    blind spot (an ATT&CK technique with zero visibility, or a simulated
#    action that was never captured) caps confidence at "acceptable" even
#    when both quality scores are individually "good", because a SOC
#    handoff with a confirmed gap should not be labeled with full
#    confidence regardless of the aggregate score. This is a deliberate
#    scoring convention for this task, not an external standard.
# ---------------------------------------------------------------------------
windows_quality_score="$(jq '.quality_score' "${WINDOWS_QUALITY_PATH}")"
linux_quality_score="$(jq '.quality_score' "${LINUX_QUALITY_PATH}")"
 
echo "Windows quality: ${windows_quality_score}"
echo "Linux quality: ${linux_quality_score}"
 
lower_score="$(awk -v w="${windows_quality_score}" -v l="${linux_quality_score}" 'BEGIN { print (w<l)?w:l }')"
has_gap=0
[[ "${attack_blind}" -gt 0 ]] && has_gap=1
[[ "${combined_det_missed}" -gt 0 ]] && has_gap=1
 
confidence="poor"
if awk -v s="${lower_score}" 'BEGIN { exit !(s>=90) }'; then
    if [[ "${has_gap}" -eq 1 ]]; then
        confidence="acceptable"
    else
        confidence="good"
    fi
elif awk -v s="${lower_score}" 'BEGIN { exit !(s>=75) }'; then
    confidence="acceptable"
fi
echo "Confidence: ${confidence}"
 
# ---------------------------------------------------------------------------
# Assemble and write the full report in one jq pass
# ---------------------------------------------------------------------------
jq -n \
    --slurpfile we "${WINDOWS_EVENTS_PATH}" \
    --slurpfile le "${LINUX_EVENTS_PATH}" \
    --slurpfile gt "${GROUND_TRUTH_PATH}" \
    --slurpfile wdet "${WINDOWS_DETECTION_PATH}" \
    --slurpfile ldet "${LINUX_DETECTION_PATH}" \
    --slurpfile wq "${WINDOWS_QUALITY_PATH}" \
    --slurpfile lq "${LINUX_QUALITY_PATH}" \
    --slurpfile sysmon "${SYSMON_COVERAGE_PATH}" \
    --arg confidence "${confidence}" \
    '
    ($we[0].events) as $wevents |
    ($le[0].events) as $levents |
    ($wevents + $levents) as $allevents |
    {
        generated: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
        total_events: {
            by_platform: { windows: ($wevents | length), linux: ($levents | length) },
            by_source_type: ($allevents | group_by(.source_type) | map({(.[0].source_type): length}) | add // {}),
            by_event_category: ($allevents | group_by(.event_category) | map({(.[0].event_category): length}) | add // {})
        },
        detection_matrix_summary: {
            total_simulated_actions: ($wdet[0].total_actions + $ldet[0].total_actions),
            captured_actions: ($wdet[0].captured_actions + $ldet[0].captured_actions),
            missed_actions: (($wdet[0].total_actions + $ldet[0].total_actions) - ($wdet[0].captured_actions + $ldet[0].captured_actions)),
            multi_source_detections: ($wdet[0].multi_source_count + $ldet[0].multi_source_count)
        },
        attack_coverage: {
            scope_note: "Reflects sysmon_coverage_matrix.json (Task 1) only - Windows/Sysmon ATT&CK mapping. No equivalent Linux/auditd ATT&CK coverage matrix exists in this module.",
            covered_techniques: $sysmon[0].covered,
            partial_techniques: $sysmon[0].partial,
            blind_techniques: $sysmon[0].blind,
            techniques: [ $sysmon[0].matrix[] | { technique_id, technique_name, coverage_status, source_responsible: .required_event_ids } ]
        },
        known_gaps: (
            [ $sysmon[0].matrix[] | select(.coverage_status != "covered") | {
                description: ("ATT&CK " + .technique_id + " (" + .technique_name + ") is " + .coverage_status),
                impacted_platform: "Windows",
                impacted_technique: .technique_id,
                reason: .reason,
                recommended_improvement: .recommendation
            } ]
            +
            [ $wdet[0].matrix[]? | select(.status == "MISSED") | {
                description: ("Simulated action \"" + .action + "\" was not captured by any Windows telemetry source"),
                impacted_platform: "Windows",
                impacted_technique: null,
                reason: "No matching event found in the +/-30s search window around the ground truth timestamp",
                recommended_improvement: "Review whether the expected Event ID/log source is enabled, unfiltered, and retained long enough on DC01"
            } ]
            +
            [ $ldet[0].matrix[]? | select(.status == "MISSED") | {
                description: ("Simulated action \"" + .action + "\" was not captured by any Linux telemetry source"),
                impacted_platform: "Linux",
                impacted_technique: null,
                reason: "No matching event found in the +/-30s search window around the ground truth timestamp",
                recommended_improvement: "Review whether the relevant auditd rule/key, auth.log or syslog pattern actually covers this action on billing-srv-01"
            } ]
        ),
        quality_summary: {
            windows_score: $wq[0].quality_score,
            windows_assessment: $wq[0].assessment,
            linux_score: $lq[0].quality_score,
            linux_assessment: $lq[0].assessment,
            final_handoff_confidence: $confidence
        },
        ground_truth_actions: $gt[0].total_actions
    }
    ' > "${OUTPUT_PATH}"
 
echo "Report saved to: ${OUTPUT_PATH}"
