#!/bin/bash
#
# script name : 13-patch_pipeline.sh
# purpose     : chain every preceding task (0 through 12, minus the
#               standalone rollback/hold-management/recovery utilities
#               that are invoked on demand rather than on every run) into
#               a single idempotent pipeline: inventory, dependency map,
#               snapshot, plan, maintenance-window check, execute,
#               validate, drift detection, change log. Stops on the first
#               stage failure. If the maintenance-window guard refuses to
#               authorize the run (any non-zero exit - out of window, or
#               only the emergency window with no override), the
#               patch-touching stages (execute/validate/drift) are
#               skipped and the run is marked "deferred" rather than
#               "failed" - the change log stage still runs, since
#               recording that a run was deferred is itself part of the
#               audit trail. Emits pipeline_run.json.
# author      : Aïda Sylla
# date        : 2026-08-14
 
set -uo pipefail
# NOTE: deliberately not using -e. A stage failing, or the pipeline being
# correctly deferred outside the maintenance window, are expected,
# meaningful outcomes this orchestrator exists to report - not script
# bugs. Every stage's exit status is captured and handled explicitly
# rather than left to propagate uncontrolled.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (most stages install packages, read root-only logs, or manage systemd state). Try: sudo $0" >&2
    exit 1
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to write the pipeline report. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${SCRIPT_DIR}/pipeline_run.json"
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
# ---------------------------------------------------------------------------
# Stage definitions: script, display-args (for the guard's --check flag),
# and the artifact JSON path each stage is expected to produce.
# ---------------------------------------------------------------------------
STAGE_SCRIPTS=(
    "0-vuln_inventory.sh"
    "1-service_deps.sh"
    "2-pre_patch_snapshot.sh"
    "3-patch_plan.sh"
    "11-maintenance_window.sh"
    "4-patch_execute.sh"
    "5-post_patch_validate.sh"
    "6-config_drift.sh"
    "12-change_log.sh"
)
STAGE_ARGS=(
    "" "" "" "" "--check" "" "" "" ""
)
STAGE_ARTIFACTS=(
    "vulnerability_inventory.json"
    "service_dependency_map.json"
    "pre_patch_state.json"
    "patch_plan.json"
    "maintenance_window.json"
    "patch_execution_log.json"
    "post_patch_validation.json"
    "config_drift.json"
    "patch_change_log.json"
)
GUARD_STAGE_INDEX=4          # 11-maintenance_window.sh --check
PATCH_TOUCHING_INDICES=(5 6 7)  # 4-patch_execute, 5-post_patch_validate, 6-config_drift
 
stage_count="${#STAGE_SCRIPTS[@]}"
started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
pipeline_start_ts="$(date +%s.%N)"
 
STAGES_JSON=()
pipeline_status="ok"
deferred="false"
guard_note=""
 
for i in $(seq 0 $((stage_count - 1))); do
    display_idx=$((i + 1))
    script="${STAGE_SCRIPTS[${i}]}"
    args="${STAGE_ARGS[${i}]}"
    artifact="${STAGE_ARTIFACTS[${i}]}"
    script_path="${SCRIPT_DIR}/${script}"
 
    # ------------------------------------------------------------------
    # Deferred pipeline: skip the patch-touching stages, but still record
    # a "skipped" entry for each so the report accounts for every stage.
    # ------------------------------------------------------------------
    is_patch_touching="false"
    for pt in "${PATCH_TOUCHING_INDICES[@]}"; do
        [[ "${i}" -eq "${pt}" ]] && is_patch_touching="true"
    done
 
    if [[ "${deferred}" == "true" && "${is_patch_touching}" == "true" ]]; then
        printf '[%s/%s] %-34s SKIPPED (deferred: %s)\n' "${display_idx}" "${stage_count}" "${script}" "${guard_note}"
        STAGES_JSON+=("$(jq -n --arg s "${script}" --arg reason "deferred: ${guard_note}" \
            '{stage: $s, status: "skipped", exit_code: null, duration_seconds: 0, reason: $reason}')")
        continue
    fi
 
    if [[ ! -x "${script_path}" ]]; then
        printf '[%s/%s] %-34s FAILED (script not found or not executable)\n' "${display_idx}" "${stage_count}" "${script}"
        STAGES_JSON+=("$(jq -n --arg s "${script}" \
            '{stage: $s, status: "failed", exit_code: null, duration_seconds: 0, reason: "script not found or not executable"}')")
        pipeline_status="failed"
        break
    fi
 
    stage_start_ts="$(date +%s.%N)"
    stdout_file="$(mktemp)"
    stderr_file="$(mktemp)"
 
    # shellcheck disable=SC2086
    "${script_path}" ${args} > "${stdout_file}" 2> "${stderr_file}"
    stage_exit=$?
 
    stage_end_ts="$(date +%s.%N)"
    duration="$(awk -v a="${stage_start_ts}" -v b="${stage_end_ts}" 'BEGIN{printf "%.1f", b-a}')"
    stdout_tail="$(tail -n 15 "${stdout_file}")"
    stderr_tail="$(tail -n 15 "${stderr_file}")"
    rm -f "${stdout_file}" "${stderr_file}"
 
    if [[ "${i}" -eq "${GUARD_STAGE_INDEX}" ]]; then
        # ------------------------------------------------------------
        # Maintenance window guard: exit 0 means authorized (a normal
        # window is active, or MEDDEFENSE_EMERGENCY=1 already granted
        # the override inside 11-maintenance_window.sh itself). Any
        # non-zero exit - 10 (emergency-only, no override) or 20
        # (outside every window) - means this run is not currently
        # authorized to touch package state, so the pipeline defers
        # rather than treating it as a failure.
        # ------------------------------------------------------------
        if [[ "${stage_exit}" -eq 0 ]]; then
            printf '[%s/%s] %-34s OK  (window authorized)\n' "${display_idx}" "${stage_count}" "${script}"
            STAGES_JSON+=("$(jq -n --arg s "${script}" --argjson ec "${stage_exit}" --argjson dur "${duration}" \
                --arg out "${stdout_tail}" --arg err "${stderr_tail}" \
                '{stage: $s, status: "ok", exit_code: $ec, duration_seconds: $dur, stdout_tail: $out, stderr_tail: $err}')")
        else
            deferred="true"
            guard_note="maintenance window guard exit ${stage_exit}"
            printf '[%s/%s] %-34s DEFERRED  (exit %s - %s)\n' "${display_idx}" "${stage_count}" "${script}" "${stage_exit}" "${guard_note}"
            STAGES_JSON+=("$(jq -n --arg s "${script}" --argjson ec "${stage_exit}" --argjson dur "${duration}" \
                --arg out "${stdout_tail}" --arg err "${stderr_tail}" \
                '{stage: $s, status: "deferred", exit_code: $ec, duration_seconds: $dur, stdout_tail: $out, stderr_tail: $err}')")
        fi
        continue
    fi
 
    if [[ "${stage_exit}" -eq 0 ]]; then
        printf '[%s/%s] %-34s OK  (%ss)\n' "${display_idx}" "${stage_count}" "${script}" "${duration}"
        STAGES_JSON+=("$(jq -n --arg s "${script}" --argjson ec "${stage_exit}" --argjson dur "${duration}" \
            --arg out "${stdout_tail}" --arg err "${stderr_tail}" \
            '{stage: $s, status: "ok", exit_code: $ec, duration_seconds: $dur, stdout_tail: $out, stderr_tail: $err}')")
    else
        printf '[%s/%s] %-34s FAILED  (exit %s, %ss) - stopping pipeline\n' "${display_idx}" "${stage_count}" "${script}" "${stage_exit}" "${duration}"
        STAGES_JSON+=("$(jq -n --arg s "${script}" --argjson ec "${stage_exit}" --argjson dur "${duration}" \
            --arg out "${stdout_tail}" --arg err "${stderr_tail}" \
            '{stage: $s, status: "failed", exit_code: $ec, duration_seconds: $dur, stdout_tail: $out, stderr_tail: $err}')")
        pipeline_status="failed"
        break
    fi
done
 
if [[ "${pipeline_status}" != "failed" && "${deferred}" == "true" ]]; then
    pipeline_status="deferred"
fi
 
finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
pipeline_end_ts="$(date +%s.%N)"
total_duration="$(awk -v a="${pipeline_start_ts}" -v b="${pipeline_end_ts}" 'BEGIN{printf "%.1f", b-a}')"
 
echo "PIPELINE: ${pipeline_status}"
echo "Duration: ${total_duration}s"
 
# ---------------------------------------------------------------------------
# Build the artifacts map (stage -> output JSON path, only for stages that
# actually ran and are expected to have produced one).
# ---------------------------------------------------------------------------
ARTIFACT_ENTRIES=()
for i in $(seq 0 $((stage_count - 1))); do
    script="${STAGE_SCRIPTS[${i}]}"
    artifact="${STAGE_ARTIFACTS[${i}]}"
    artifact_path="${SCRIPT_DIR}/${artifact}"
    if [[ -f "${artifact_path}" ]]; then
        ARTIFACT_ENTRIES+=("$(jq -n --arg s "${script}" --arg p "${artifact_path}" '{($s): $p}')")
    fi
done
ARTIFACTS_JSON="$(printf '%s\n' "${ARTIFACT_ENTRIES[@]}" | jq -s 'add // {}')"
 
STAGES_ARRAY_JSON="[$(IFS=,; echo "${STAGES_JSON[*]:-}")]"
 
jq -n \
    --arg started "${started_at}" \
    --arg finished "${finished_at}" \
    --arg hostname "$(hostname)" \
    --arg status "${pipeline_status}" \
    --argjson stages "${STAGES_ARRAY_JSON}" \
    --argjson artifacts "${ARTIFACTS_JSON}" \
    --argjson duration "${total_duration}" \
    '{started_at: $started, finished_at: $finished, hostname: $hostname,
      pipeline_status: $status, duration_seconds: $duration,
      stages: $stages, artifacts: $artifacts}' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
 
if [[ "${pipeline_status}" == "failed" ]]; then
    exit 1
else
    exit 0
fi
