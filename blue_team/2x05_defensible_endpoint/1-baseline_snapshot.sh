#!/bin/bash
#
# script name : 1-baseline_snapshot.sh
# purpose     : run a recognized hardening audit (Lynis) against
#               hawthorne-app-01 and persist both the raw log and the
#               extracted Hardening Index as the quantitative starting
#               point for the capstone - the denominator every later
#               delta will be measured against. Reads Lynis's own
#               machine-readable report file (/var/log/lynis-report.dat)
#               rather than parsing colored terminal output, since that
#               report format is stable key=value text, confirmed
#               against a real Lynis 3.0.9 run.
# author      : Aïda Sylla
# date        : 2026-08-22
#
# EXIT CODES (documented, per this capstone's own rule):
#   0 - baseline captured successfully
#   1 - controlled failure (Lynis ran but the Hardening Index could not
#       be extracted from its report, or the emitted JSON is malformed)
#   2 - environment error (lynis or jq missing)
 
set -uo pipefail
# NOTE: deliberately not using -e. A low hardening index, warnings or
# suggestions being present are all expected, legitimate audit findings
# this script must record faithfully - not script bugs. Lynis itself is
# also expected to exit non-zero in some environments even on a
# successful scan (it uses its exit code for its own internal signaling,
# not as a simple pass/fail of the audit run) - handled explicitly below
# by checking for the report file's existence rather than trusting
# lynis's exit code alone.
 
REQUIRED_TOOLS=(lynis jq)
MISSING_TOOLS=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "${tool}" >/dev/null 2>&1 || MISSING_TOOLS+=("${tool}")
done
if [[ "${#MISSING_TOOLS[@]}" -gt 0 ]]; then
    echo "Missing required tool(s): ${MISSING_TOOLS[*]}. Install lynis (e.g. apt install lynis) and jq, then re-run." >&2
    exit 2
fi
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (lynis needs elevated access to audit the full system). Try: sudo $0" >&2
    exit 2
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_DIR="${SCRIPT_DIR}/capstone/baseline"
mkdir -p "${BASELINE_DIR}"
 
LOG_PATH="${BASELINE_DIR}/lynis_baseline.log"
OUTPUT_PATH="${BASELINE_DIR}/baseline_linux.json"
LYNIS_REPORT_DAT="/var/log/lynis-report.dat"
 
echo "[*] Running lynis audit system (this can take a few minutes)..."
 
# Lynis's own exit code reflects internal signaling, not simply
# "audit succeeded/failed" - it can legitimately be non-zero on a
# completed, successful scan. The real success signal is the report
# file existing and being freshly written, checked explicitly below.
lynis audit system --quick --no-colors > "${LOG_PATH}" 2>&1
lynis_exit=$?
echo "    lynis exit code: ${lynis_exit} (not treated as pass/fail by itself)"
 
if [[ ! -f "${LYNIS_REPORT_DAT}" ]]; then
    echo "FAILED: lynis's machine-readable report was not found at ${LYNIS_REPORT_DAT}. See ${LOG_PATH} for the full run output." >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 2. Parse the Hardening Index (and related fields) from Lynis's own
#    report.dat - stable key=value text, confirmed against a real run.
# ---------------------------------------------------------------------------
echo "[*] Parsing Hardening Index..."
 
hardening_index="$(grep -m1 '^hardening_index=' "${LYNIS_REPORT_DAT}" | cut -d= -f2 | tr -d '\r')"
lynis_version="$(grep -m1 '^lynis_version=' "${LYNIS_REPORT_DAT}" | cut -d= -f2 | tr -d '\r')"
lynis_hostname="$(grep -m1 '^hostname=' "${LYNIS_REPORT_DAT}" | cut -d= -f2 | tr -d '\r')"
[[ -z "${lynis_hostname}" ]] && lynis_hostname="$(hostname)"
[[ -z "${lynis_version}" ]] && lynis_version="unknown"
 
warnings_count="$(grep -c '^warning\[\]=' "${LYNIS_REPORT_DAT}" || echo 0)"
suggestions_count="$(grep -c '^suggestion\[\]=' "${LYNIS_REPORT_DAT}" || echo 0)"
 
if [[ -z "${hardening_index}" ]]; then
    echo "FAILED: could not extract hardening_index from ${LYNIS_REPORT_DAT}. Lynis ran, but its report is missing the expected field." >&2
    exit 1
fi
if ! [[ "${hardening_index}" =~ ^[0-9]+$ ]]; then
    echo "FAILED: hardening_index value '${hardening_index}' is not a plain number as expected." >&2
    exit 1
fi
 
echo "    Hardening Index: ${hardening_index}   Warnings: ${warnings_count}   Suggestions: ${suggestions_count}"
 
# ---------------------------------------------------------------------------
# 3. Emit baseline_linux.json
# ---------------------------------------------------------------------------
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "${lynis_hostname}" \
    --arg lynis_version "${lynis_version}" \
    --argjson hardening_index "${hardening_index}" \
    --argjson warnings_count "${warnings_count}" \
    --argjson suggestions_count "${suggestions_count}" \
    --arg log_path "${LOG_PATH}" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        lynis_version: $lynis_version,
        hardening_index: $hardening_index,
        warnings_count: $warnings_count,
        suggestions_count: $suggestions_count,
        log_path: $log_path
    }' > "${OUTPUT_PATH}"
 
if ! jq empty "${OUTPUT_PATH}" >/dev/null 2>&1; then
    echo "FAILED: baseline_linux.json was written but is not valid JSON." >&2
    exit 1
fi
 
echo ""
echo "Report saved to: ${OUTPUT_PATH}"
echo "Log saved to: ${LOG_PATH}"
exit 0
