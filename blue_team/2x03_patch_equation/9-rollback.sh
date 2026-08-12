#!/bin/bash
#
# script name : 9-rollback.sh
# purpose     : downgrade a single package back to the version recorded in
#               pre_patch_state.json (Task 2), confirm that version is
#               actually resolvable via apt-cache madison before touching
#               anything, execute the downgrade, hold the package so
#               unattended-upgrades does not immediately re-upgrade it,
#               re-run the Task 5 liveness probes for every affected
#               service, and print a clear rollback summary. This is the
#               reversibility path every patch in this project depends on.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -uo pipefail
# NOTE: deliberately not using -e. A version not found in the snapshot, an
# unavailable target version, or a failed probe are expected, meaningful
# outcomes this script exists to report - not script bugs. Every command
# whose non-zero exit is normal control flow is handled explicitly.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it downgrades packages, applies a hold, and may restart-probe services). Try: sudo $0 <package>" >&2
    exit 1
fi
 
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <package>" >&2
    exit 1
fi
PACKAGE="$1"
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to read the input files. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRE_STATE_PATH="${SCRIPT_DIR}/pre_patch_state.json"
SVC_MAP_PATH="${SCRIPT_DIR}/service_dependency_map.json"
PROBES_PATH="${SCRIPT_DIR}/service_probes.json"
APT_CALL_TIMEOUT=600
 
if [[ ! -f "${PRE_STATE_PATH}" ]]; then
    echo "pre_patch_state.json not found at ${PRE_STATE_PATH}. Cannot determine a rollback target without it." >&2
    exit 1
fi
if ! jq empty "${PRE_STATE_PATH}" >/dev/null 2>&1; then
    echo "pre_patch_state.json is not valid JSON: ${PRE_STATE_PATH}" >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 2/3. Target version lookup.
#    NOTE: the task's own instructions describe this as `packages[<name>]`,
#    implying a dict keyed by package name. This project's actual
#    pre_patch_state.json (as produced by 2-pre_patch_snapshot.sh and
#    already deployed on billing-srv-01) stores "packages" as an ARRAY of
#    {package, version} objects instead. Rather than break compatibility
#    with the real, already-running snapshot format, this lookup is
#    adapted to that array schema - functionally the same dict-by-name
#    lookup the task describes, just matched to our actual data shape.
# ---------------------------------------------------------------------------
TARGET_VERSION="$(jq -r --arg p "${PACKAGE}" '.packages[]? | select(.package == $p) | .version' "${PRE_STATE_PATH}" | head -1)"
 
if [[ -z "${TARGET_VERSION}" || "${TARGET_VERSION}" == "null" ]]; then
    echo "FAILED: '${PACKAGE}' is not present in pre_patch_state.json - no rollback target version on record. Nothing was changed." >&2
    exit 1
fi
 
echo "[*] Target version from pre_patch_state.json: ${TARGET_VERSION}"
 
CURRENT_VERSION="$(dpkg-query -W -f='${Version}' "${PACKAGE}" 2>/dev/null || echo "")"
if [[ -z "${CURRENT_VERSION}" ]]; then
    echo "Warning: '${PACKAGE}' does not appear to be currently installed (dpkg-query found nothing). Proceeding anyway - apt-get install will handle installing it at the target version." >&2
    CURRENT_VERSION="not installed"
fi
 
# ---------------------------------------------------------------------------
# 4. Confirm the target version is resolvable via apt-cache madison.
# ---------------------------------------------------------------------------
MADISON_OUTPUT="$(apt-cache madison "${PACKAGE}" 2>/dev/null || true)"
if grep -qF "${TARGET_VERSION}" <<< "${MADISON_OUTPUT}"; then
    version_available="yes"
else
    version_available="no"
fi
echo "[*] Version available in cache or repository: ${version_available}"
 
if [[ "${version_available}" != "yes" ]]; then
    echo "FAILED: target version ${TARGET_VERSION} of ${PACKAGE} is not resolvable via apt-cache madison (not in the local cache or any configured repository). Rollback cannot proceed - nothing was changed." >&2
    echo ""
    echo "ROLLBACK: failed (version unavailable)"
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 5. Execute the downgrade.
#    Same hard-won safety flags as 4-patch_execute.sh and 7-apt_recovery.sh
#    (found for real on billing-srv-01: a stdin read can hang indefinitely,
#    needrestart can try to prompt, a conffile prompt needs an explicit
#    default) - a downgrade is the same class of apt/dpkg invocation and
#    carries the same risks.
# ---------------------------------------------------------------------------
echo -n "[*] Downgrading ${PACKAGE}...                              "
 
downgrade_output_file="$(mktemp)"
timeout "${APT_CALL_TIMEOUT}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    apt-get install -y --allow-downgrades \
    -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    "${PACKAGE}=${TARGET_VERSION}" \
    < /dev/null > "${downgrade_output_file}" 2>&1
downgrade_status=$?
downgrade_output="$(cat "${downgrade_output_file}")"
rm -f "${downgrade_output_file}"
 
if [[ "${downgrade_status}" -eq 0 ]]; then
    echo "OK"
    downgrade_ok="true"
else
    echo "FAILED"
    echo "    exit ${downgrade_status}: $(tail -n 5 <<< "${downgrade_output}")" >&2
    downgrade_ok="false"
fi
 
# ---------------------------------------------------------------------------
# 6. apt-mark hold, only if the downgrade actually succeeded - holding a
#    package that is NOT at the intended version would just lock in a
#    half-finished rollback.
# ---------------------------------------------------------------------------
hold_ok="false"
if [[ "${downgrade_ok}" == "true" ]]; then
    echo -n "[*] apt-mark hold ${PACKAGE}                               "
    if apt-mark hold "${PACKAGE}" >/dev/null 2>&1; then
        echo "OK"
        hold_ok="true"
    else
        echo "FAILED"
    fi
fi
 
# ---------------------------------------------------------------------------
# 7. Re-run Task 5's liveness probes for every service whose
#    linked_packages contains this package.
#    service_probes.json schema (same assumption documented in
#    5-post_patch_validate.sh):
#      { "<service>": { "type": "http", "url": "...", "expected_status": 200 } }
#      { "<service>": { "type": "command", "command": "..." } }
# ---------------------------------------------------------------------------
PROBE_RESULTS=()
all_probes_passed="true"
 
if [[ "${downgrade_ok}" == "true" && -f "${SVC_MAP_PATH}" ]] && jq empty "${SVC_MAP_PATH}" >/dev/null 2>&1; then
    echo "[*] Re-running probes for affected services..."
    mapfile -t AFFECTED_SERVICES < <(jq -r --arg p "${PACKAGE}" '
        .services[]? | select(.linked_packages | index($p) != null) | .service
    ' "${SVC_MAP_PATH}" 2>/dev/null | sort -u)
 
    HAVE_PROBES=false
    if [[ -f "${PROBES_PATH}" ]] && jq empty "${PROBES_PATH}" >/dev/null 2>&1; then
        HAVE_PROBES=true
    fi
 
    for svc in "${AFFECTED_SERVICES[@]}"; do
        [[ -z "${svc}" ]] && continue
 
        if [[ "${HAVE_PROBES}" != true ]]; then
            printf '    %-38s %s\n' "${svc} probe" "SKIPPED (no service_probes.json)"
            PROBE_RESULTS+=("$(jq -n --arg s "${svc}" '{service: $s, result: "skipped", detail: "no service_probes.json"}')")
            continue
        fi
 
        probe_def="$(jq -c --arg s "${svc}" '.[$s] // empty' "${PROBES_PATH}")"
        if [[ -z "${probe_def}" ]]; then
            printf '    %-38s %s\n' "${svc} probe" "SKIPPED (no probe defined)"
            PROBE_RESULTS+=("$(jq -n --arg s "${svc}" '{service: $s, result: "skipped", detail: "no probe defined for this service"}')")
            continue
        fi
 
        probe_type="$(jq -r '.type' <<< "${probe_def}")"
        probe_result="FAIL"
        probe_detail=""
 
        case "${probe_type}" in
            http)
                url="$(jq -r '.url' <<< "${probe_def}")"
                expected_status="$(jq -r '.expected_status // 200' <<< "${probe_def}")"
                actual_status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${url}" 2>/dev/null || echo "000")"
                if [[ "${actual_status}" == "${expected_status}" ]]; then
                    probe_result="PASS"
                else
                    probe_result="FAIL"
                    all_probes_passed="false"
                fi
                probe_detail="HTTP ${actual_status} from ${url}"
                ;;
            command)
                cmd="$(jq -r '.command' <<< "${probe_def}")"
                if timeout 10 bash -c "${cmd}" >/dev/null 2>&1; then
                    probe_result="PASS"
                else
                    probe_result="FAIL"
                    all_probes_passed="false"
                fi
                probe_detail="command: ${cmd}"
                ;;
            *)
                probe_result="FAIL"
                all_probes_passed="false"
                probe_detail="unknown probe type '${probe_type}'"
                ;;
        esac
 
        printf '    %-38s %s\n' "${svc} probe" "${probe_result}"
        PROBE_RESULTS+=("$(jq -n --arg s "${svc}" --arg r "${probe_result}" --arg d "${probe_detail}" '{service: $s, result: $r, detail: $d}')")
    done
elif [[ "${downgrade_ok}" != "true" ]]; then
    all_probes_passed="false"
fi
 
# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
overall_success="false"
if [[ "${downgrade_ok}" == "true" && "${hold_ok}" == "true" && "${all_probes_passed}" == "true" ]]; then
    overall_success="true"
fi
 
echo ""
if [[ "${overall_success}" == "true" ]]; then
    echo "ROLLBACK: success"
else
    echo "ROLLBACK: failed"
fi
echo "from ${CURRENT_VERSION} to ${TARGET_VERSION}"
 
if [[ "${overall_success}" == "true" ]]; then
    exit 0
else
    exit 1
fi
