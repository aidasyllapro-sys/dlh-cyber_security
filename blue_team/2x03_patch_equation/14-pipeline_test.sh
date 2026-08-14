#!/bin/bash
#
# script name : 14-pipeline_test.sh
# purpose     : prove the pipeline handles a fresh advisory correctly by
#               swapping in a simulated CVE feed, running the full
#               pipeline in dry-run mode (PIPELINE_TEST=1, so
#               4-patch_execute.sh simulates rather than applies), and
#               comparing the resulting patch_plan.json against a
#               project-supplied expected plan (with timestamps
#               normalized before the diff). Always restores the real
#               cve_feed.json afterward, success or failure, via trap.
#               Emits pipeline_test_results.json.
# author      : Aïda Sylla
# date        : 2026-08-14
 
set -uo pipefail
# NOTE: deliberately not using -e. A plan mismatch, or a pipeline stage
# behaving differently under the simulated advisory, are expected,
# meaningful test outcomes this script exists to report - not script
# bugs. Every command whose non-zero exit is normal control flow is
# handled explicitly. Restoration of cve_feed.json is guaranteed via trap
# regardless of how this script exits.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it invokes the full patch pipeline). Try: sudo $0" >&2
    exit 1
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE_FEED_PATH="${SCRIPT_DIR}/cve_feed.json"
CVE_FEED_BACKUP="${SCRIPT_DIR}/cve_feed.json.bak"
SIMULATED_FEED_PATH="${SCRIPT_DIR}/cve_feed.simulated.json"
EXPECTED_PLAN_PATH="${SCRIPT_DIR}/patch_plan.expected.json"
PLAN_PATH="${SCRIPT_DIR}/patch_plan.json"
PIPELINE_SCRIPT="${SCRIPT_DIR}/13-patch_pipeline.sh"
PIPELINE_RUN_PATH="${SCRIPT_DIR}/pipeline_run.json"
OUTPUT_PATH="${SCRIPT_DIR}/pipeline_test_results.json"
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
echo "[*] Scenario: simulated CVE advisory"
 
if [[ ! -f "${SIMULATED_FEED_PATH}" ]]; then
    echo "cve_feed.simulated.json not found at ${SIMULATED_FEED_PATH} - this fixture must be supplied by the project before this test can run. Nothing was changed." >&2
    exit 1
fi
if ! jq empty "${SIMULATED_FEED_PATH}" >/dev/null 2>&1; then
    echo "cve_feed.simulated.json is not valid JSON: ${SIMULATED_FEED_PATH}" >&2
    exit 1
fi
 
if [[ ! -x "${PIPELINE_SCRIPT}" ]]; then
    echo "13-patch_pipeline.sh not found or not executable at ${PIPELINE_SCRIPT}." >&2
    exit 1
fi
 
started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
had_original_feed="false"
 
# ---------------------------------------------------------------------------
# Guaranteed restoration of cve_feed.json, whatever happens next. This is
# the safety net that makes it safe to inject a simulated advisory at all:
# even a crash or an unexpected exit must never leave a fake CVE feed in
# place on a system other tasks (and real operators) rely on.
# ---------------------------------------------------------------------------
restore_feed() {
    if [[ "${had_original_feed}" == "true" && -f "${CVE_FEED_BACKUP}" ]]; then
        mv "${CVE_FEED_BACKUP}" "${CVE_FEED_PATH}"
    elif [[ "${had_original_feed}" != "true" ]]; then
        rm -f "${CVE_FEED_PATH}"
    fi
}
trap restore_feed EXIT INT TERM
 
# ---------------------------------------------------------------------------
# 1. Backup the current cve_feed.json (if any).
# ---------------------------------------------------------------------------
echo -n "[*] Backing up cve_feed.json...              "
if [[ -f "${CVE_FEED_PATH}" ]]; then
    cp "${CVE_FEED_PATH}" "${CVE_FEED_BACKUP}"
    had_original_feed="true"
    echo "OK"
else
    echo "OK (no existing cve_feed.json - none to back up)"
fi
 
# ---------------------------------------------------------------------------
# 2. Inject the simulated advisory.
# ---------------------------------------------------------------------------
echo -n "[*] Injecting cve_feed.simulated.json...     "
cp "${SIMULATED_FEED_PATH}" "${CVE_FEED_PATH}"
echo "OK"
 
# ---------------------------------------------------------------------------
# 3. Run the pipeline in dry-run mode.
# ---------------------------------------------------------------------------
echo "[*] Running pipeline (PIPELINE_TEST=1)..."
PIPELINE_TEST=1 "${PIPELINE_SCRIPT}"
pipeline_exit=$?
 
stages_ok="true"
[[ "${pipeline_exit}" -ne 0 ]] && stages_ok="false"
 
# ---------------------------------------------------------------------------
# 4. Compare patch_plan.json against the expected plan, timestamps
#    normalized to a fixed placeholder before diffing.
# ---------------------------------------------------------------------------
plan_matches_expected="false"
DIFF_LINES=()
 
if [[ ! -f "${EXPECTED_PLAN_PATH}" ]]; then
    echo "[*] Comparing patch_plan.json to expected...  SKIPPED (patch_plan.expected.json not supplied)"
    DIFF_LINES+=("patch_plan.expected.json not found - comparison skipped, cannot confirm a match")
elif [[ ! -f "${PLAN_PATH}" ]]; then
    echo "[*] Comparing patch_plan.json to expected...  FAILED (patch_plan.json was not produced)"
    DIFF_LINES+=("patch_plan.json was not produced by this run")
else
    # Normalize any field commonly holding a timestamp to a fixed
    # placeholder in both files before diffing, so a legitimate run-to-run
    # timestamp difference never causes a false mismatch.
    norm_actual="$(jq 'walk(if type == "object" then with_entries(if (.key == "generated_at" or .key == "timestamp" or .key == "now") then .value = "TIMESTAMP" else . end) else . end)' "${PLAN_PATH}" 2>/dev/null)"
    norm_expected="$(jq 'walk(if type == "object" then with_entries(if (.key == "generated_at" or .key == "timestamp" or .key == "now") then .value = "TIMESTAMP" else . end) else . end)' "${EXPECTED_PLAN_PATH}" 2>/dev/null)"
 
    actual_tmp="$(mktemp)"
    expected_tmp="$(mktemp)"
    jq -S '.' <<< "${norm_actual}" > "${actual_tmp}" 2>/dev/null
    jq -S '.' <<< "${norm_expected}" > "${expected_tmp}" 2>/dev/null
 
    if diff -q "${actual_tmp}" "${expected_tmp}" >/dev/null 2>&1; then
        plan_matches_expected="true"
        echo "[*] Comparing patch_plan.json to expected...  match"
    else
        echo "[*] Comparing patch_plan.json to expected...  MISMATCH"
        mapfile -t DIFF_LINES < <(diff -u "${expected_tmp}" "${actual_tmp}")
    fi
    rm -f "${actual_tmp}" "${expected_tmp}"
fi
 
# ---------------------------------------------------------------------------
# 5. Validate pipeline_run.json status and that every stage produced a
#    non-empty artifact.
# ---------------------------------------------------------------------------
artifacts_ok="true"
if [[ -f "${PIPELINE_RUN_PATH}" ]] && jq empty "${PIPELINE_RUN_PATH}" >/dev/null 2>&1; then
    pipeline_status="$(jq -r '.pipeline_status' "${PIPELINE_RUN_PATH}")"
    if [[ "${pipeline_status}" != "ok" && "${pipeline_status}" != "deferred" ]]; then
        stages_ok="false"
    fi
 
    mapfile -t artifact_paths < <(jq -r '.artifacts[]? // empty' "${PIPELINE_RUN_PATH}" 2>/dev/null)
    for ap in "${artifact_paths[@]}"; do
        [[ -z "${ap}" ]] && continue
        if [[ ! -s "${ap}" ]]; then
            artifacts_ok="false"
            DIFF_LINES+=("artifact missing or empty: ${ap}")
        fi
    done
else
    stages_ok="false"
    artifacts_ok="false"
    DIFF_LINES+=("pipeline_run.json was not produced or is not valid JSON")
fi
 
# ---------------------------------------------------------------------------
# 6. Restore cve_feed.json (trap already guarantees this on exit, but do it
#    now too so the printed summary reflects the real end state before
#    this script terminates).
# ---------------------------------------------------------------------------
echo -n "[*] Restoring cve_feed.json...                "
restore_feed
trap - EXIT INT TERM
echo "OK"
 
# ---------------------------------------------------------------------------
# 7. Verdict and report
# ---------------------------------------------------------------------------
verdict="pass"
if [[ "${stages_ok}" != "true" || "${artifacts_ok}" != "true" || "${plan_matches_expected}" != "true" ]]; then
    verdict="fail"
fi
 
echo "VERDICT: ${verdict}"
 
finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
 
DIFF_JSON="[$(for l in "${DIFF_LINES[@]}"; do printf '"%s",' "$(json_escape "${l}")"; done | sed 's/,$//')]"
 
jq -n \
    --arg scenario "simulated CVE advisory" \
    --arg started "${started_at}" \
    --arg finished "${finished_at}" \
    --argjson stages_ok "${stages_ok}" \
    --argjson plan_matches "${plan_matches_expected}" \
    --argjson diff "${DIFF_JSON}" \
    --arg verdict "${verdict}" \
    '{scenario: $scenario, started_at: $started, finished_at: $finished,
      stages_ok: $stages_ok, plan_matches_expected: $plan_matches,
      diff: $diff, verdict: $verdict}' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
 
if [[ "${verdict}" == "pass" ]]; then
    exit 0
else
    exit 1
fi
