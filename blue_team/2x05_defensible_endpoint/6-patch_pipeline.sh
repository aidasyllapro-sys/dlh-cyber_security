#!/bin/bash
#
# script name : 6-patch_pipeline.sh
# purpose     : deploy the patch management pipeline on hawthorne-app-01
#               end-to-end - this script does not reinvent the pipeline
#               (2x03_patch_equation/13-patch_pipeline.sh already does
#               the real work, validated on billing-srv-01). It wraps
#               that pipeline with client-specific directory redirection
#               (CAPSTONE_ARTIFACTS_DIR), points it at the capstone's own
#               CVE feed and blacklist, and emits a summary the rest of
#               this capstone can read without re-deriving anything.
# author      : Aïda Sylla
# date        : 2026-08-22
#
# EXIT CODES (documented, per this capstone's own rule):
#   0 - the underlying pipeline exited 0 AND failed_entries == 0
#   1 - controlled failure (the pipeline exited non-zero, or
#       failed_entries > 0)
#   2 - environment error (the pipeline script, CVE feed, or blacklist
#       file is missing)
#
# ASSUMPTION - pipeline calling convention: 13-patch_pipeline.sh's own
# argument/env-var conventions for accepting a CVE feed path were not
# available when this script was written. Both an environment variable
# (CVE_FEED_PATH) and a positional argument are passed through below as
# a hedge - confirm against the real script on hawthorne-app-01 and
# drop whichever one it does not actually use.
#
# ASSUMPTION - unattended-upgrades configuration: this wrapper invokes
# 2x03_patch_equation/8-unattended_config.sh (the real script for this,
# already validated on billing-srv-01) with the capstone blacklist path,
# assuming it accepts a blacklist file path as its first argument - its
# real calling convention was not available when this script was
# written; confirm and adjust before trusting this step.
 
set -uo pipefail
# NOTE: deliberately not using -e. A non-zero pipeline exit code or a
# non-zero failed_entries count are expected, meaningful outcomes this
# script exists to detect and report - not script bugs.
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_SCRIPTS_DIR="${PATCH_SCRIPTS_DIR:-${SCRIPT_DIR}/../2x03_patch_equation}"
PIPELINE_SCRIPT="${PATCH_SCRIPTS_DIR}/13-patch_pipeline.sh"
UNATTENDED_CONFIG_SCRIPT="${PATCH_SCRIPTS_DIR}/8-unattended_config.sh"
 
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
# Per this task's own instructions, every pipeline sub-step artifact
# must land inside capstone/patch/.
export CAPSTONE_ARTIFACTS_DIR="capstone/patch/"
PATCH_ARTIFACTS_DIR="${SCRIPT_DIR}/${CAPSTONE_ARTIFACTS_DIR}"
mkdir -p "${PATCH_ARTIFACTS_DIR}"
 
CVE_FEED_PATH="/home/analyst/MedDefense_Lab/capstone/cve_feed.json"
BLACKLIST_PATH="/home/analyst/MedDefense_Lab/capstone/blacklist.json"
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it and re-run." >&2
    exit 2
fi
 
if [[ ! -x "${PIPELINE_SCRIPT}" ]]; then
    echo "FATAL: pipeline script not found or not executable at ${PIPELINE_SCRIPT}." >&2
    exit 2
fi
if [[ ! -f "${CVE_FEED_PATH}" ]]; then
    echo "FATAL: capstone CVE feed not found at ${CVE_FEED_PATH}." >&2
    exit 2
fi
if [[ ! -f "${BLACKLIST_PATH}" ]]; then
    echo "FATAL: capstone blacklist not found at ${BLACKLIST_PATH}." >&2
    exit 2
fi
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (the underlying patch pipeline needs elevated access). Try: sudo $0" >&2
    exit 2
fi
 
echo "[*] Configuring unattended-upgrades with the mandated blacklist..."
if [[ -x "${UNATTENDED_CONFIG_SCRIPT}" ]]; then
    "${UNATTENDED_CONFIG_SCRIPT}" "${BLACKLIST_PATH}"
    unattended_exit=$?
    echo "    unattended-upgrades config exit: ${unattended_exit}"
else
    echo "Warning: ${UNATTENDED_CONFIG_SCRIPT} not found or not executable - unattended-upgrades blacklist step skipped." >&2
    unattended_exit=127
fi
 
echo "[*] Invoking the patch pipeline with CAPSTONE_ARTIFACTS_DIR=${CAPSTONE_ARTIFACTS_DIR}..."
start_ts="$(date +%s.%N)"
CVE_FEED_PATH="${CVE_FEED_PATH}" "${PIPELINE_SCRIPT}" "${CVE_FEED_PATH}" > "${PATCH_ARTIFACTS_DIR}/pipeline_stdout.log" 2>&1
pipeline_exit=$?
end_ts="$(date +%s.%N)"
duration="$(awk -v s="${start_ts}" -v e="${end_ts}" 'BEGIN{printf "%.2f", e - s}')"
echo "    pipeline exit code: ${pipeline_exit}   duration: ${duration}s"
 
# ---------------------------------------------------------------------------
# 4. Capture every sub-step artifact path that landed in
#    CAPSTONE_ARTIFACTS_DIR.
# ---------------------------------------------------------------------------
mapfile -t ARTIFACT_FILES < <(find "${PATCH_ARTIFACTS_DIR}" -maxdepth 1 -type f 2>/dev/null | sort)
ARTIFACTS_JSON="[$(for f in "${ARTIFACT_FILES[@]}"; do printf '"%s",' "${f}"; done | sed 's/,$//')]"
echo "    ${#ARTIFACT_FILES[@]} artifact(s) captured in ${PATCH_ARTIFACTS_DIR}."
 
# ---------------------------------------------------------------------------
# 5. Read failed_entries from the pipeline's own execution log, per this
#    task's own explicit field name.
# ---------------------------------------------------------------------------
EXECUTION_LOG_PATH="${PATCH_ARTIFACTS_DIR}/patch_execution_log.json"
failed_entries="null"
if [[ -f "${EXECUTION_LOG_PATH}" ]] && jq empty "${EXECUTION_LOG_PATH}" >/dev/null 2>&1; then
    failed_entries="$(jq -r '.failed_entries // "null"' "${EXECUTION_LOG_PATH}")"
fi
 
if [[ "${failed_entries}" == "null" ]]; then
    echo "Warning: could not read failed_entries from ${EXECUTION_LOG_PATH} - treating as a controlled failure since it cannot be confirmed as zero." >&2
    failed_entries_numeric=-1
else
    failed_entries_numeric="${failed_entries}"
fi
 
echo "    failed_entries: ${failed_entries}"
 
# ---------------------------------------------------------------------------
# Emit a summary report.
# ---------------------------------------------------------------------------
SUMMARY_PATH="${CAPSTONE_DIR}/exec/patch_pipeline_summary.json"
mkdir -p "$(dirname "${SUMMARY_PATH}")"
 
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson pipeline_exit_code "${pipeline_exit}" \
    --arg duration_seconds "${duration}" \
    --argjson unattended_config_exit "${unattended_exit}" \
    --argjson artifacts "${ARTIFACTS_JSON}" \
    --arg failed_entries "${failed_entries}" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        pipeline_exit_code: $pipeline_exit_code,
        duration_seconds: ($duration_seconds | tonumber),
        unattended_config_exit: $unattended_config_exit,
        artifacts: $artifacts,
        failed_entries: $failed_entries
    }' > "${SUMMARY_PATH}"
 
if ! jq empty "${SUMMARY_PATH}" >/dev/null 2>&1; then
    echo "FAILED: ${SUMMARY_PATH} was written but is not valid JSON." >&2
    exit 1
fi
 
echo ""
echo "Summary saved to: ${SUMMARY_PATH}"
 
# ---------------------------------------------------------------------------
# Final exit logic: 0 only if pipeline exited 0 AND failed_entries == 0.
# ---------------------------------------------------------------------------
if [[ "${pipeline_exit}" -eq 0 ]] && [[ "${failed_entries_numeric}" -eq 0 ]]; then
    echo "PASS: pipeline succeeded and failed_entries == 0."
    exit 0
else
    echo "FAIL: pipeline_exit=${pipeline_exit} failed_entries=${failed_entries}" >&2
    exit 1
fi
