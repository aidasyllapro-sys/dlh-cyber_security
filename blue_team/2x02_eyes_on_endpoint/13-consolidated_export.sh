#!/bin/bash
#
# script name : 13-consolidated_export.sh
# purpose     : combine the Windows telemetry export (Task 3), the Linux
#               telemetry export (Task 7), and both attacker-simulation
#               ground truth files (Tasks 9 and 11) into a single handoff
#               package for Module 3. Verifies both platforms' events carry
#               the required common fields (timestamp, hostname,
#               source_type, event_category), verifies every timestamp is
#               already normalized UTC ISO 8601, and writes
#               telemetry_handoff/windows_events.json,
#               telemetry_handoff/linux_events.json and
#               telemetry_handoff/attack_ground_truth.json (combined
#               Windows + Linux ground truth).
#               Uses jq for all JSON parsing - a real JSON parser is
#               required here, not text-based extraction, because the
#               Windows exports come from PowerShell's ConvertTo-Json
#               (pretty-printed, multi-line) while the Linux exports come
#               from this module's own bash scripts (compact, single-line);
#               jq handles both identically since it parses structure
#               rather than text layout.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
 
WINDOWS_EVENTS_PATH="windows_events_export.json"
LINUX_EVENTS_PATH="linux_events_export.json"
WINDOWS_ATTACK_LOG_PATH="windows_attack_log.json"
LINUX_ATTACK_LOG_PATH="linux_attack_log.json"
HANDOFF_DIR="telemetry_handoff"
 
while [[ $# -gt 0 ]]; do
    case "$1" in
        --windows-events) WINDOWS_EVENTS_PATH="$2"; shift 2 ;;
        --linux-events)   LINUX_EVENTS_PATH="$2"; shift 2 ;;
        --windows-attack) WINDOWS_ATTACK_LOG_PATH="$2"; shift 2 ;;
        --linux-attack)   LINUX_ATTACK_LOG_PATH="$2"; shift 2 ;;
        --output-dir)     HANDOFF_DIR="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to parse and merge JSON across platforms. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
for f in "${WINDOWS_EVENTS_PATH}" "${LINUX_EVENTS_PATH}" "${WINDOWS_ATTACK_LOG_PATH}" "${LINUX_ATTACK_LOG_PATH}"; do
    if [[ ! -f "${f}" ]]; then
        echo "Required input file not found: ${f}" >&2
        exit 1
    fi
    if ! jq empty "${f}" >/dev/null 2>&1; then
        echo "File is not valid JSON: ${f}" >&2
        exit 1
    fi
done
 
windows_count="$(jq '.events | length' "${WINDOWS_EVENTS_PATH}")"
echo "[*] Loading Windows events (${windows_count})..."
 
linux_count="$(jq '.events | length' "${LINUX_EVENTS_PATH}")"
echo "[*] Loading Linux events (${linux_count})..."
 
# ---------------------------------------------------------------------------
# Normalize timestamps to UTC ISO 8601
#    Both upstream scripts (3-windows_telemetry_export.ps1 and
#    7-linux_export.sh) already emit strict "YYYY-MM-DDTHH:MM:SSZ" UTC
#    timestamps. This step VERIFIES that rather than blindly assuming it -
#    if any event's timestamp does not already match that exact pattern,
#    it is reported as needing normalization; this script does not attempt
#    to guess-convert an unrecognized timestamp format, since a wrong
#    guess would silently corrupt evidence. Fix the upstream export instead
#    if this ever reports a non-zero count.
# ---------------------------------------------------------------------------
echo "[*] Normalizing timestamps to UTC..."
 
ISO_UTC_REGEX='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
 
windows_nonconforming="$(jq --arg re "${ISO_UTC_REGEX}" '[.events[].timestamp | select(test($re) | not)] | length' "${WINDOWS_EVENTS_PATH}")"
linux_nonconforming="$(jq --arg re "${ISO_UTC_REGEX}" '[.events[].timestamp | select(test($re) | not)] | length' "${LINUX_EVENTS_PATH}")"
 
windows_normalized=$((windows_count - windows_nonconforming))
linux_normalized=$((linux_count - linux_nonconforming))
 
echo "    Windows: ${windows_normalized} events normalized"
echo "    Linux: ${linux_normalized} events normalized"
 
if [[ "${windows_nonconforming}" -gt 0 || "${linux_nonconforming}" -gt 0 ]]; then
    echo "    WARNING: Windows has ${windows_nonconforming} and Linux has ${linux_nonconforming} timestamp(s) not in strict UTC ISO 8601 format - fix the upstream export script rather than trusting a blind auto-conversion here." >&2
fi
 
# ---------------------------------------------------------------------------
# Verify field consistency across platforms
# ---------------------------------------------------------------------------
echo "[*] Verifying field consistency..."
 
required_fields_ok="$(jq '[.events[] | (has("timestamp") and has("hostname") and has("source_type") and has("event_category"))] | all' "${WINDOWS_EVENTS_PATH}")"
required_fields_ok_linux="$(jq '[.events[] | (has("timestamp") and has("hostname") and has("source_type") and has("event_category"))] | all' "${LINUX_EVENTS_PATH}")"
 
if [[ "${required_fields_ok}" == "true" && "${required_fields_ok_linux}" == "true" ]]; then
    echo "    Required fields present in all events    [OK]"
    fields_status="OK"
else
    echo "    Required fields missing on one or more events    [FAIL]" >&2
    fields_status="FAIL"
fi
 
# ---------------------------------------------------------------------------
# Combine ground truth
# ---------------------------------------------------------------------------
echo "[*] Combining ground truth..."
 
windows_actions="$(jq '.ground_truth | length' "${WINDOWS_ATTACK_LOG_PATH}")"
linux_actions="$(jq '.ground_truth | length' "${LINUX_ATTACK_LOG_PATH}")"
total_actions=$((windows_actions + linux_actions))
 
echo "    Windows actions: ${windows_actions} | Linux actions: ${linux_actions} | Total: ${total_actions}"
 
# ---------------------------------------------------------------------------
# Build handoff directory
# ---------------------------------------------------------------------------
echo "[*] Building handoff directory..."
mkdir -p "${HANDOFF_DIR}"
 
jq '.' "${WINDOWS_EVENTS_PATH}" > "${HANDOFF_DIR}/windows_events.json"
jq '.' "${LINUX_EVENTS_PATH}" > "${HANDOFF_DIR}/linux_events.json"
 
jq -n \
    --slurpfile w "${WINDOWS_ATTACK_LOG_PATH}" \
    --slurpfile l "${LINUX_ATTACK_LOG_PATH}" \
    '{
        windows: $w[0].ground_truth,
        linux: $l[0].ground_truth,
        windows_actions: ($w[0].ground_truth | length),
        linux_actions: ($l[0].ground_truth | length),
        total_actions: (($w[0].ground_truth | length) + ($l[0].ground_truth | length))
    }' > "${HANDOFF_DIR}/attack_ground_truth.json"
 
human_size() {
    local bytes
    bytes="$(stat -c %s "$1" 2>/dev/null || echo 0)"
    awk -v b="${bytes}" 'BEGIN {
        if (b >= 1048576) { printf "%.1f MB", b/1048576 }
        else if (b >= 1024) { printf "%.1f KB", b/1024 }
        else { printf "%d B", b }
    }'
}
 
windows_size="$(human_size "${HANDOFF_DIR}/windows_events.json")"
linux_size="$(human_size "${HANDOFF_DIR}/linux_events.json")"
 
echo "${HANDOFF_DIR}/"
echo "  windows_events.json     (${windows_count} events, ${windows_size})"
echo "  linux_events.json       (${linux_count} events, ${linux_size})"
echo "  attack_ground_truth.json (${total_actions} actions)"
 
total_events=$((windows_count + linux_count))
echo "Total: ${total_events} events across 2 platforms"
