#!/bin/bash
#
# script name : 4-patch_execute.sh
# purpose     : execute patch_plan.json (Task 3) in order, safely: acquire
#               an exclusive advisory lock so two instances can never run
#               concurrently, capture a pre-check (installed version,
#               linked-service states) and a post-check for every package
#               before and after `apt-get install --only-upgrade -y`,
#               handle a busy dpkg lock with exponential backoff instead
#               of failing immediately, try-restart every affected service
#               when the plan calls for it (and no reboot is required
#               instead), and record every action - pre, post, exit
#               status, stdout/stderr tail, duration - as structured JSON
#               in patch_execution_log.json. On the first failed patch,
#               stop applying further entries but still finalize the log
#               for everything already attempted.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -uo pipefail
# NOTE: deliberately not using -e here. This script's entire purpose is to
# run a command (apt-get install) that is EXPECTED to sometimes fail as
# part of normal operation - a failed patch is a recorded outcome, not a
# script bug, and the log for everything attempted so far must still be
# written when that happens. Every command whose failure is normal control
# flow is handled explicitly with its own if/case check; nothing is
# accidentally masked by omission.
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAN_PATH="${SCRIPT_DIR}/patch_plan.json"
OUTPUT_PATH="${SCRIPT_DIR}/patch_execution_log.json"
LOCK_FILE="/var/lock/meddefense-patch.lock"
LOCK_FD=200
DPKG_LOCK_MAX_WAIT=120
STDOUT_TAIL_LINES=20
STDERR_TAIL_LINES=20
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it installs packages and restarts services). Try: sudo $0" >&2
    exit 2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to read patch_plan.json and write the execution log. Install it (e.g. apt install jq) and re-run." >&2
    exit 2
fi
 
if [[ ! -f "${PLAN_PATH}" ]]; then
    echo "patch_plan.json not found at ${PLAN_PATH}. Run 3-patch_plan.sh first." >&2
    exit 2
fi
if ! jq empty "${PLAN_PATH}" >/dev/null 2>&1; then
    echo "patch_plan.json is not valid JSON: ${PLAN_PATH}" >&2
    exit 2
fi
 
# ---------------------------------------------------------------------------
# 1. Advisory lock via flock. Holding the lock on file descriptor 200 for
#    the life of this process is what makes release automatic and safe
#    even on a hard kill: the kernel closes every open fd (and releases
#    any flock held on it) the instant the process exits, for ANY reason.
#    The explicit trap below is for clear logging/cleanup, not the actual
#    safety net - the fd closing is.
# ---------------------------------------------------------------------------
echo -n "[*] Acquiring lock ${LOCK_FILE}...  "
 
eval "exec ${LOCK_FD}>\"${LOCK_FILE}\""
if ! flock -n "${LOCK_FD}"; then
    echo "FAILED"
    echo "Another instance is already running (lock held on ${LOCK_FILE})." >&2
    exit 2
fi
echo "OK"
 
cleanup() {
    flock -u "${LOCK_FD}" 2>/dev/null || true
    eval "exec ${LOCK_FD}>&-"
}
trap cleanup EXIT INT TERM
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
tail_lines() {
    local text="$1" n="$2"
    printf '%s' "${text}" | tail -n "${n}"
}
 
get_installed_version() {
    local pkg="$1"
    dpkg-query -W -f='${Version}' "${pkg}" 2>/dev/null || echo ""
}
 
# Same order-independent KEY=value parsing as 2-pre_patch_snapshot.sh -
# `systemctl show` does not guarantee its output follows the order the -p
# flags were given on the command line (confirmed the hard way on
# billing-srv-01 in Task 2).
get_service_state() {
    local svc="$1" show_out active_state sub_state
    [[ "${svc}" == "(kernel-wide)" ]] && { echo '{"service":"(kernel-wide)","active_state":null,"sub_state":null}'; return; }
    show_out="$(systemctl show -p ActiveState -p SubState "${svc}" 2>/dev/null || true)"
    active_state="$(grep -oP '^ActiveState=\K.*' <<< "${show_out}" || true)"
    sub_state="$(grep -oP '^SubState=\K.*' <<< "${show_out}" || true)"
    printf '{"service":"%s","active_state":"%s","sub_state":"%s"}' \
        "$(json_escape "${svc}")" "$(json_escape "${active_state}")" "$(json_escape "${sub_state}")"
}
 
get_services_state_block() {
    local services_json="$1" parts=() svc svc_list
    mapfile -t svc_list < <(jq -r '.[]' <<< "${services_json}" 2>/dev/null)
    for svc in "${svc_list[@]}"; do
        [[ -z "${svc}" ]] && continue
        parts+=("$(get_service_state "${svc}")")
    done
    printf '[%s]' "$(IFS=,; echo "${parts[*]:-}")"
}
 
plan_source_hash="$(sha256sum "${PLAN_PATH}" | awk '{print $1}')"
entry_count="$(jq '.plan | length' "${PLAN_PATH}")"
echo "[*] Loading plan: $(basename "${PLAN_PATH}") (${entry_count} entries)"
 
ENTRY_LOGS=()
succeeded_count=0
failed_count=0
stopped_early="false"
started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
 
for idx in $(seq 0 $((entry_count - 1))); do
    pkg="$(jq -r ".plan[${idx}].package" "${PLAN_PATH}")"
    bucket="$(jq -r ".plan[${idx}].bucket" "${PLAN_PATH}")"
    requires_restart="$(jq -r ".plan[${idx}].requires_restart" "${PLAN_PATH}")"
    requires_reboot="$(jq -r ".plan[${idx}].requires_reboot" "${PLAN_PATH}")"
    affected_services_json="$(jq -c ".plan[${idx}].affected_services" "${PLAN_PATH}")"
 
    display_idx=$((idx + 1))
 
    if [[ "${stopped_early}" == "true" ]]; then
        entry=$(jq -n --arg pkg "${pkg}" --arg bucket "${bucket}" \
            '{package: $pkg, bucket: $bucket, status: "skipped", reason: "execution stopped after an earlier failure"}')
        ENTRY_LOGS+=("${entry}")
        printf '[%s/%s] %-20s %-13s SKIPPED (stopped after earlier failure)\n' "${display_idx}" "${entry_count}" "${pkg}" "${bucket}"
        continue
    fi
 
    pre_version="$(get_installed_version "${pkg}")"
    pre_services="$(get_services_state_block "${affected_services_json}")"
    pre_block="$(jq -n --arg v "${pre_version}" --argjson svc "${pre_services}" '{installed_version: $v, services: $svc}')"
 
    start_ts="$(date -u +%s.%N)"
 
    # ---------------------------------------------------------------------
    # 2 & 3. apt-get install --only-upgrade, with exponential backoff on a
    # busy dpkg lock rather than failing on the very first contention.
    # ---------------------------------------------------------------------
    attempt=0
    waited=0
    backoff=2
    apt_exit=1
    apt_stdout=""
    apt_stderr=""
    failure_reason=""
    APT_CALL_TIMEOUT=600
 
    while true; do
        attempt=$((attempt + 1))
        apt_stdout_file="$(mktemp)"
        apt_stderr_file="$(mktemp)"
        # NOTE: found the hard way on billing-srv-01 - DEBIAN_FRONTEND=
        # noninteractive alone does NOT guarantee apt-get/dpkg never reads
        # from the terminal. A dpkg trigger hook (needrestart's
        # dpkg-status script) blocked indefinitely on a real terminal read
        # (n_tty_read in its kernel stack) during a live run, hanging the
        # whole patch pipeline with no way to recover on its own. Three
        # independent fixes, all required:
        #   - </dev/null: nothing this command spawns can block waiting
        #     for keyboard input, because there is no input to wait for.
        #   - NEEDRESTART_MODE=a: tells needrestart's hooks to run in
        #     automatic mode instead of attempting an interactive prompt.
        #   - timeout: a hard ceiling so a hang becomes a clean recorded
        #     failure instead of blocking this script (and the lock it
        #     holds) forever.
        #   - Dpkg::Options::="--force-confdef"/"--force-confold": found
        #     the hard way right after fixing the stdin hang above - with
        #     stdin redirected to /dev/null, a dpkg conffile prompt (a
        #     locally modified /etc config file colliding with the
        #     package maintainer's new version) got an immediate EOF
        #     instead of hanging, but dpkg treated that EOF as a failed
        #     answer ("end of file on stdin at conffile prompt") rather
        #     than a safe default - confirmed on billing-srv-01 with
        #     ubuntu-pro-client. These two options are the standard,
        #     documented way to make dpkg resolve conffile prompts
        #     automatically (keep the local modification unless there is
        #     none, in which case take the new version) instead of ever
        #     prompting - the same convention unattended-upgrades itself
        #     relies on for unattended security patching.
        timeout "${APT_CALL_TIMEOUT}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
            apt-get install --only-upgrade -y \
            -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
            "${pkg}" \
            < /dev/null > "${apt_stdout_file}" 2> "${apt_stderr_file}"
        apt_exit=$?
        apt_stdout="$(cat "${apt_stdout_file}")"
        apt_stderr="$(cat "${apt_stderr_file}")"
        rm -f "${apt_stdout_file}" "${apt_stderr_file}"
 
        if [[ "${apt_exit}" -eq 124 ]]; then
            failure_reason="apt-get timed out after ${APT_CALL_TIMEOUT}s (possible hung dpkg trigger/hook - check for a stuck process before retrying manually)"
            break
        fi
 
        if [[ "${apt_exit}" -eq 0 ]]; then
            break
        fi
 
        if grep -qi "Could not get lock\|Unable to acquire the dpkg frontend lock" <<< "${apt_stderr}"; then
            if [[ "${waited}" -ge "${DPKG_LOCK_MAX_WAIT}" ]]; then
                failure_reason="dpkg lock still busy after waiting ${waited}s (max ${DPKG_LOCK_MAX_WAIT}s)"
                break
            fi
            sleep "${backoff}"
            waited=$((waited + backoff))
            backoff=$((backoff * 2))
            continue
        fi
 
        # Any other failure is not a lock contention - stop retrying.
        break
    done
 
    end_ts="$(date -u +%s.%N)"
    duration_seconds="$(awk -v a="${start_ts}" -v b="${end_ts}" 'BEGIN { printf "%.1f", b - a }')"
 
    post_version="$(get_installed_version "${pkg}")"
    post_services="$(get_services_state_block "${affected_services_json}")"
    post_block="$(jq -n --arg v "${post_version}" --argjson svc "${post_services}" '{installed_version: $v, services: $svc}')"
 
    stdout_tail="$(tail_lines "${apt_stdout}" "${STDOUT_TAIL_LINES}")"
    stderr_tail="$(tail_lines "${apt_stderr}" "${STDERR_TAIL_LINES}")"
 
    if [[ "${apt_exit}" -ne 0 ]]; then
        status="failed"
        failed_count=$((failed_count + 1))
        stopped_early="true"
        reason="${failure_reason:-apt-get exited with status ${apt_exit}}"
        printf '[%s/%s] %-20s %-13s apt-get ... FAILED (%s) - stopping further patches\n' \
            "${display_idx}" "${entry_count}" "${pkg}" "${bucket}" "${reason}"
 
        entry=$(jq -n \
            --arg pkg "${pkg}" --arg bucket "${bucket}" --arg status "${status}" \
            --argjson pre "${pre_block}" --argjson post "${post_block}" \
            --argjson duration "${duration_seconds}" --argjson exit_code "${apt_exit}" \
            --arg reason "${reason}" --arg stdout_tail "${stdout_tail}" --arg stderr_tail "${stderr_tail}" \
            '{package: $pkg, bucket: $bucket, status: $status, pre: $pre, post: $post,
              duration_seconds: $duration, exit_code: $exit_code, reason: $reason,
              stdout_tail: $stdout_tail, stderr_tail: $stderr_tail, restarts: []}')
        ENTRY_LOGS+=("${entry}")
        continue
    fi
 
    status="succeeded"
    succeeded_count=$((succeeded_count + 1))
    printf '[%s/%s] %-20s %-13s apt-get ... OK (%ss)\n' "${display_idx}" "${entry_count}" "${pkg}" "${bucket}" "${duration_seconds}"
 
    # ---------------------------------------------------------------------
    # try-restart affected services, only if the plan calls for a restart
    # and no full reboot is required instead (a per-service restart makes
    # no sense when the whole system needs to come down anyway).
    # ---------------------------------------------------------------------
    RESTART_RESULTS=()
    if [[ "${requires_restart}" == "true" && "${requires_reboot}" != "true" ]]; then
        mapfile -t restart_svcs < <(jq -r '.[]' <<< "${affected_services_json}" 2>/dev/null)
        for svc in "${restart_svcs[@]}"; do
            [[ -z "${svc}" || "${svc}" == "(kernel-wide)" ]] && continue
            if systemctl try-restart "${svc}" >/dev/null 2>&1; then
                printf '      try-restart %-30s OK\n' "${svc}"
                RESTART_RESULTS+=("$(jq -n --arg s "${svc}" '{service: $s, result: "OK"}')")
            else
                printf '      try-restart %-30s FAILED\n' "${svc}"
                RESTART_RESULTS+=("$(jq -n --arg s "${svc}" '{service: $s, result: "FAILED"}')")
            fi
        done
    fi
    restarts_json="[$(IFS=,; echo "${RESTART_RESULTS[*]:-}")]"
 
    entry=$(jq -n \
        --arg pkg "${pkg}" --arg bucket "${bucket}" --arg status "${status}" \
        --argjson pre "${pre_block}" --argjson post "${post_block}" \
        --argjson duration "${duration_seconds}" --argjson exit_code "${apt_exit}" \
        --arg stdout_tail "${stdout_tail}" --arg stderr_tail "${stderr_tail}" \
        --argjson restarts "${restarts_json}" \
        '{package: $pkg, bucket: $bucket, status: $status, pre: $pre, post: $post,
          duration_seconds: $duration, exit_code: $exit_code,
          stdout_tail: $stdout_tail, stderr_tail: $stderr_tail, restarts: $restarts}')
    ENTRY_LOGS+=("${entry}")
done
 
finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
 
echo "Succeeded: ${succeeded_count}  Failed: ${failed_count}"
 
# ---------------------------------------------------------------------------
# 4. Write patch_execution_log.json
# ---------------------------------------------------------------------------
ENTRIES_JSON="[$(IFS=,; echo "${ENTRY_LOGS[*]:-}")]"
 
jq -n \
    --arg started_at "${started_at}" \
    --arg finished_at "${finished_at}" \
    --arg hostname "$(hostname)" \
    --arg plan_source_hash "${plan_source_hash}" \
    --argjson entries "${ENTRIES_JSON}" \
    '{started_at: $started_at, finished_at: $finished_at, hostname: $hostname,
      plan_source_hash: $plan_source_hash, entries: $entries}' > "${OUTPUT_PATH}"
 
echo "Log saved to: $(basename "${OUTPUT_PATH}")"
 
# ---------------------------------------------------------------------------
# 5. Exit code
# ---------------------------------------------------------------------------
if [[ "${failed_count}" -gt 0 ]]; then
    exit 1
fi
exit 0
