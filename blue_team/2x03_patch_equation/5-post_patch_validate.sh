#!/bin/bash
#
# script name : 5-post_patch_validate.sh
# purpose     : close the validation loop after a patch run - for every
#               service recorded in pre_patch_state.json (Task 2), verify
#               its current ActiveState is the same quality or better than
#               before patching; for every socket recorded in the
#               pre-patch snapshot, verify it is still listening; for
#               every service marked "critical" in
#               service_dependency_map.json (Task 1), run its liveness
#               probe from the companion service_probes.json file.
#               Classifies every check as pass / regression / probe_failed
#               and emits post_patch_validation.json.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -uo pipefail
# NOTE: deliberately not using -e. This script's entire purpose is to
# detect and report failures (a regressed service, a probe that fails) -
# those are expected, meaningful outcomes to record, not script bugs. Every
# command whose non-zero exit is normal control flow is handled explicitly.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "Warning: not running as root. systemctl show and ss -tulnp may return incomplete results without full privileges. Try: sudo $0" >&2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to read the input files and write the report. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRE_STATE_PATH="${SCRIPT_DIR}/pre_patch_state.json"
SVC_MAP_PATH="${SCRIPT_DIR}/service_dependency_map.json"
PROBES_PATH="${SCRIPT_DIR}/service_probes.json"
OUTPUT_PATH="${SCRIPT_DIR}/post_patch_validation.json"
 
if [[ ! -f "${PRE_STATE_PATH}" ]]; then
    echo "pre_patch_state.json not found at ${PRE_STATE_PATH}. Run 2-pre_patch_snapshot.sh before patching, next time." >&2
    exit 1
fi
if ! jq empty "${PRE_STATE_PATH}" >/dev/null 2>&1; then
    echo "pre_patch_state.json is not valid JSON: ${PRE_STATE_PATH}" >&2
    exit 1
fi
 
HAVE_SVC_MAP=false
if [[ -f "${SVC_MAP_PATH}" ]] && jq empty "${SVC_MAP_PATH}" >/dev/null 2>&1; then
    HAVE_SVC_MAP=true
else
    echo "Warning: service_dependency_map.json not found or invalid - critical liveness probes will be skipped entirely." >&2
fi
 
HAVE_PROBES=false
if [[ -f "${PROBES_PATH}" ]] && jq empty "${PROBES_PATH}" >/dev/null 2>&1; then
    HAVE_PROBES=true
else
    echo "Warning: service_probes.json not found or invalid - critical liveness probes will be skipped entirely." >&2
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
DETAILS=()
pass_count=0
fail_count=0
 
add_detail() {
    local check_type="$1" target="$2" status="$3" detail_msg="$4"
    if [[ "${status}" == "pass" ]]; then
        pass_count=$((pass_count + 1))
    else
        fail_count=$((fail_count + 1))
    fi
    DETAILS+=("$(jq -n --arg t "${check_type}" --arg target "${target}" --arg status "${status}" --arg msg "${detail_msg}" \
        '{check_type: $t, target: $target, status: $status, detail: $msg}')")
}
 
# ---------------------------------------------------------------------------
# ActiveState quality ordinal, for "same or better" regression detection.
#    systemd does not itself define a single linear quality ranking across
#    ActiveState values - this ordinal is a reasonable, documented
#    engineering interpretation for THIS check (active is best, failed is
#    worst), not an official systemd ranking. Adjust if your program
#    expects different regression semantics (e.g. any state change at all
#    counts as a regression, regardless of direction).
# ---------------------------------------------------------------------------
active_state_ordinal() {
    case "$1" in
        active)      echo 3 ;;
        activating)  echo 2 ;;
        reloading)   echo 2 ;;
        inactive)    echo 1 ;;
        deactivating) echo 1 ;;
        failed)      echo 0 ;;
        "")          echo 0 ;;
        *)           echo 1 ;;
    esac
}
 
get_current_active_state() {
    local svc="$1" show_out
    show_out="$(systemctl show -p ActiveState "${svc}" 2>/dev/null || true)"
    grep -oP '^ActiveState=\K.*' <<< "${show_out}" || true
}
 
# ---------------------------------------------------------------------------
# 1. Service state checks
# ---------------------------------------------------------------------------
echo "[*] Checking service states against pre-patch baseline..."
svc_pass=0
svc_total=0
 
mapfile -t PRE_SERVICES < <(jq -c '.services[]?' "${PRE_STATE_PATH}")
for entry in "${PRE_SERVICES[@]}"; do
    [[ -z "${entry}" ]] && continue
    svc_total=$((svc_total + 1))
    svc_name="$(jq -r '.service' <<< "${entry}")"
    pre_state="$(jq -r '.active_state' <<< "${entry}")"
 
    current_state="$(get_current_active_state "${svc_name}")"
    pre_ord="$(active_state_ordinal "${pre_state}")"
    cur_ord="$(active_state_ordinal "${current_state}")"
 
    if [[ "${cur_ord}" -ge "${pre_ord}" ]]; then
        add_detail "service_state" "${svc_name}" "pass" "ActiveState=${current_state} (was ${pre_state})"
        svc_pass=$((svc_pass + 1))
    else
        add_detail "service_state" "${svc_name}" "regression" "ActiveState degraded from '${pre_state}' to '${current_state}'"
    fi
done
echo "Service state checks:     ${svc_pass}/${svc_total}   $( [[ "${svc_pass}" -eq "${svc_total}" ]] && echo PASS || echo FAIL )"
 
# ---------------------------------------------------------------------------
# 2. Listening socket checks
# ---------------------------------------------------------------------------
echo "[*] Checking listening sockets against pre-patch baseline..."
sock_pass=0
sock_total=0
 
CURRENT_LISTENING="$(ss -tulnp 2>/dev/null || true)"
 
mapfile -t PRE_SOCKETS < <(jq -c '.listening[]?' "${PRE_STATE_PATH}")
for entry in "${PRE_SOCKETS[@]}"; do
    [[ -z "${entry}" ]] && continue
    sock_total=$((sock_total + 1))
    proto="$(jq -r '.protocol' <<< "${entry}")"
    local_addr="$(jq -r '.local_address' <<< "${entry}")"
 
    if awk -v proto="${proto}" -v addr="${local_addr}" '$1==proto && $5==addr {found=1} END{exit !found}' <<< "${CURRENT_LISTENING}"; then
        add_detail "listening_socket" "${proto} ${local_addr}" "pass" "still listening"
        sock_pass=$((sock_pass + 1))
    else
        add_detail "listening_socket" "${proto} ${local_addr}" "regression" "no longer listening on ${local_addr}/${proto}"
    fi
done
echo "Listening socket checks:  ${sock_pass}/${sock_total}   $( [[ "${sock_pass}" -eq "${sock_total}" ]] && echo PASS || echo FAIL )"
 
# ---------------------------------------------------------------------------
# 3. Critical liveness probes
#    service_probes.json is NOT defined by this task's own data model -
#    schema assumed here (documented, to be confirmed against the real
#    project-supplied file):
#      { "<service>": { "type": "http", "url": "...", "expected_status": 200 } }
#      { "<service>": { "type": "command", "command": "mysqladmin ping" } }
# ---------------------------------------------------------------------------
echo "[*] Running critical service liveness probes..."
probe_pass=0
probe_total=0
 
if [[ "${HAVE_SVC_MAP}" == true && "${HAVE_PROBES}" == true ]]; then
    mapfile -t CRITICAL_SERVICES < <(jq -r '.services[]? | select(.criticality=="critical") | .service' "${SVC_MAP_PATH}")
    for svc in "${CRITICAL_SERVICES[@]}"; do
        [[ -z "${svc}" ]] && continue
        probe_def="$(jq -c --arg s "${svc}" '.[$s] // empty' "${PROBES_PATH}")"
        if [[ -z "${probe_def}" ]]; then
            continue
        fi
        probe_total=$((probe_total + 1))
        probe_type="$(jq -r '.type' <<< "${probe_def}")"
 
        case "${probe_type}" in
            http)
                url="$(jq -r '.url' <<< "${probe_def}")"
                expected_status="$(jq -r '.expected_status // 200' <<< "${probe_def}")"
                actual_status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${url}" 2>/dev/null || echo "000")"
                if [[ "${actual_status}" == "${expected_status}" ]]; then
                    add_detail "liveness_probe" "${svc}" "pass" "HTTP ${actual_status} from ${url}"
                    probe_pass=$((probe_pass + 1))
                else
                    add_detail "liveness_probe" "${svc}" "probe_failed" "HTTP ${actual_status} from ${url} (expected ${expected_status})"
                fi
                ;;
            command)
                cmd="$(jq -r '.command' <<< "${probe_def}")"
                if timeout 10 bash -c "${cmd}" >/dev/null 2>&1; then
                    add_detail "liveness_probe" "${svc}" "pass" "command succeeded: ${cmd}"
                    probe_pass=$((probe_pass + 1))
                else
                    add_detail "liveness_probe" "${svc}" "probe_failed" "command failed: ${cmd}"
                fi
                ;;
            *)
                add_detail "liveness_probe" "${svc}" "probe_failed" "unknown probe type '${probe_type}' in service_probes.json"
                ;;
        esac
    done
fi
echo "Critical liveness probes: ${probe_pass}/${probe_total}     $( [[ "${probe_pass}" -eq "${probe_total}" ]] && echo PASS || echo FAIL )"
 
# ---------------------------------------------------------------------------
# Verdict + write report
# ---------------------------------------------------------------------------
total_checks=$((svc_total + sock_total + probe_total))
total_passed=$((svc_pass + sock_pass + probe_pass))
total_failed=$((total_checks - total_passed))
 
if [[ "${total_failed}" -eq 0 ]]; then
    verdict="PASS"
else
    verdict="FAIL"
fi
echo "VERDICT: ${verdict} (${total_passed}/${total_checks})"
 
DETAILS_JSON="[$(IFS=,; echo "${DETAILS[*]:-}")]"
 
jq -n \
    --argjson total "${total_checks}" \
    --argjson passed "${total_passed}" \
    --argjson failed "${total_failed}" \
    --arg verdict "${verdict}" \
    --argjson details "${DETAILS_JSON}" \
    '{total_checks: $total, passed: $passed, failed: $failed, verdict: $verdict, details: $details}' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
 
if [[ "${total_failed}" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
