#!/bin/bash
#
# script name : 7-apt_recovery.sh
# purpose     : diagnose and repair a Linux system left in a broken
#               package state by an interrupted upgrade - detect live
#               dpkg/apt processes and refuse to proceed if any are found,
#               inspect the three dpkg/apt lock files, run and parse
#               dpkg --audit, list packages stuck half-configured/
#               half-installed/unpacked/triggers-pending, check free space,
#               then repair in strict order (remove only confirmed-stale
#               locks, dpkg --configure -a, apt-get --fix-broken install,
#               re-audit), restart every service whose package was in the
#               broken set, and emit a structured apt_recovery.json.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -uo pipefail
# NOTE: deliberately not using -e. This script's entire purpose is
# diagnosis and repair of an already-broken system - dpkg --audit
# reporting problems, a repair step needing to be attempted and its
# outcome recorded, are expected, meaningful conditions, not script bugs.
# Every command whose non-zero exit is normal control flow is handled
# explicitly.
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVC_MAP_PATH="${SCRIPT_DIR}/service_dependency_map.json"
OUTPUT_PATH="${SCRIPT_DIR}/apt_recovery.json"
APT_CALL_TIMEOUT=600
 
LOCK_FILES=(
    "/var/lib/dpkg/lock-frontend"
    "/var/lib/dpkg/lock"
    "/var/cache/apt/archives/lock"
)
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it inspects dpkg locks, repairs package state, and restarts services). Try: sudo $0" >&2
    exit 2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to write the recovery report. Install it (e.g. apt install jq) and re-run." >&2
    exit 2
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
start_ts="$(date -u +%s.%N)"
 
echo "[*] Diagnosing..."
 
# ---------------------------------------------------------------------------
# 1a. Live dpkg/apt processes
#    Word-bounded pattern so this doesn't false-match unrelated commands
#    that merely contain "apt" as a substring (e.g. "adapt", "aptitude"
#    intentionally included since it's dpkg-related; kept narrow otherwise).
# ---------------------------------------------------------------------------
LIVE_PROCESSES="$(pgrep -fa '(^|/)(dpkg|apt-get|apt|aptitude)(\s|$)' 2>/dev/null | grep -v "$$\|7-apt_recovery.sh" || true)"
 
if [[ -n "${LIVE_PROCESSES}" ]]; then
    echo "    live dpkg/apt processes: FOUND"
    echo "${LIVE_PROCESSES}" | sed 's/^/        /'
else
    echo "    live dpkg/apt processes: none"
fi
 
# ---------------------------------------------------------------------------
# 1b. Lock file inspection. A lock file that exists while NO live dpkg/apt
#    process was found in 1a is, by definition, stale: dpkg/apt hold these
#    via flock, which the kernel releases automatically the instant the
#    owning process exits, for any reason - the same mechanism this
#    project's own 4-patch_execute.sh relies on for its own lock safety.
# ---------------------------------------------------------------------------
EXISTING_LOCKS=()
for lock in "${LOCK_FILES[@]}"; do
    [[ -f "${lock}" ]] && EXISTING_LOCKS+=("${lock}")
done
if [[ "${#EXISTING_LOCKS[@]}" -gt 0 ]]; then
    echo "    stale locks: $(IFS=,; echo "${EXISTING_LOCKS[*]}" | sed 's/,/, /g')"
else
    echo "    stale locks: none"
fi
 
# ---------------------------------------------------------------------------
# 1c. dpkg --audit
# ---------------------------------------------------------------------------
AUDIT_OUTPUT="$(dpkg --audit 2>/dev/null || true)"
mapfile -t AUDIT_PACKAGES < <(grep -oP '^ \K\S+' <<< "${AUDIT_OUTPUT}" | sort -u)
 
# ---------------------------------------------------------------------------
# 1d. Packages stuck half-configured / half-installed / unpacked /
#    triggers-pending, via dpkg -l status flags (2nd column of the status
#    field: U=Unpacked, F=Half-conf, H=Half-inst, t=trig-pend).
# ---------------------------------------------------------------------------
mapfile -t STUCK_PACKAGES < <(dpkg -l 2>/dev/null | awk '$1 ~ /^.[UFHt]/ {print $2}' | sort -u)
 
# Union of both detection methods, deduplicated - the definitive broken set.
declare -A BROKEN_SET
for p in "${AUDIT_PACKAGES[@]}" "${STUCK_PACKAGES[@]}"; do
    [[ -n "${p}" ]] && BROKEN_SET["${p}"]=1
done
BROKEN_PACKAGES=("${!BROKEN_SET[@]}")
IFS=$'\n' BROKEN_PACKAGES=($(sort <<< "${BROKEN_PACKAGES[*]:-}")); unset IFS
 
echo "    dpkg --audit: $( [[ "${#BROKEN_PACKAGES[@]}" -eq 0 ]] && echo "clean" || (IFS=,; echo "${BROKEN_PACKAGES[*]}" | sed 's/,/, /g') )"
echo "    broken packages: ${#BROKEN_PACKAGES[@]}"
 
# ---------------------------------------------------------------------------
# 1e. Free space on / and /var
# ---------------------------------------------------------------------------
ROOT_AVAIL_KB="$(df -k / 2>/dev/null | awk 'NR==2{print $4}')"
VAR_AVAIL_KB="$(df -k /var 2>/dev/null | awk 'NR==2{print $4}')"
 
BROKEN_PKGS_JSON="[$(for p in "${BROKEN_PACKAGES[@]}"; do [[ -n "${p}" ]] && printf '"%s",' "$(json_escape "${p}")"; done | sed 's/,$//')]"
LOCKS_JSON="[$(for l in "${EXISTING_LOCKS[@]}"; do printf '"%s",' "$(json_escape "${l}")"; done | sed 's/,$//')]"
 
INITIAL_DIAGNOSIS=$(jq -n \
    --argjson has_live_process "$( [[ -n "${LIVE_PROCESSES}" ]] && echo true || echo false )" \
    --arg live_processes "${LIVE_PROCESSES}" \
    --argjson locks "${LOCKS_JSON}" \
    --arg audit_raw "${AUDIT_OUTPUT}" \
    --argjson broken_packages "${BROKEN_PKGS_JSON}" \
    --argjson root_avail_kb "${ROOT_AVAIL_KB:-0}" \
    --argjson var_avail_kb "${VAR_AVAIL_KB:-0}" \
    '{
        live_dpkg_apt_processes: (if $has_live_process then ($live_processes | split("\n") | map(select(length > 0))) else [] end),
        existing_lock_files: $locks,
        dpkg_audit_raw: $audit_raw,
        broken_packages: $broken_packages,
        broken_package_count: ($broken_packages | length),
        free_space_kb: { root: $root_avail_kb, var: $var_avail_kb }
    }')
 
# ---------------------------------------------------------------------------
# 2. Refuse to proceed if a live dpkg/apt process is detected.
# ---------------------------------------------------------------------------
if [[ -n "${LIVE_PROCESSES}" ]]; then
    echo "REFUSING: a live dpkg/apt process is running. Wait for it to finish, or investigate it directly - this script will not touch a system with an in-progress package operation." >&2
    end_ts="$(date -u +%s.%N)"
    duration="$(awk -v a="${start_ts}" -v b="${end_ts}" 'BEGIN{printf "%.0f", b-a}')"
    jq -n --argjson diag "${INITIAL_DIAGNOSIS}" --argjson duration "${duration}" \
        '{initial_diagnosis: $diag, actions_taken: [], final_state: null, recovered: false, duration_seconds: $duration, refused: true}' > "${OUTPUT_PATH}"
    exit 2
fi
 
# ---------------------------------------------------------------------------
# 3. Repair, in strict order.
# ---------------------------------------------------------------------------
ACTIONS=()
 
add_action() {
    local action="$1" status="$2" detail="$3"
    ACTIONS+=("$(jq -n --arg a "${action}" --arg s "${status}" --arg d "${detail}" '{action: $a, status: $s, detail: $d}')")
    printf '    %-38s %s\n' "${action}" "${status}"
}
 
echo "[*] Repairing..."
 
# --- 3a. Remove only confirmed-stale locks (we already proved no live
#     process holds them, above, before we ever reach this point) ---
if [[ "${#EXISTING_LOCKS[@]}" -gt 0 ]]; then
    removed_any=false
    for lock in "${EXISTING_LOCKS[@]}"; do
        if rm -f "${lock}" 2>/dev/null; then
            removed_any=true
        fi
    done
    if [[ "${removed_any}" == true ]]; then
        add_action "remove stale locks" "OK" "removed: $(IFS=,; echo "${EXISTING_LOCKS[*]}")"
    else
        add_action "remove stale locks" "FAILED" "could not remove one or more lock files"
    fi
else
    add_action "remove stale locks" "SKIPPED" "no lock files present"
fi
 
# --- 3b. dpkg --configure -a ---
configure_output="$(dpkg --configure -a 2>&1)"
configure_status=$?
if [[ "${configure_status}" -eq 0 ]]; then
    add_action "dpkg --configure -a" "OK" "$(tail -n 5 <<< "${configure_output}")"
else
    add_action "dpkg --configure -a" "FAILED" "exit ${configure_status}: $(tail -n 10 <<< "${configure_output}")"
fi
 
# --- 3c. apt-get --fix-broken install ---
# Same hard-won safety flags as 4-patch_execute.sh (found for real on
# billing-srv-01: a stdin read can hang indefinitely, needrestart can try
# to prompt, and a conffile prompt needs an explicit default) - this is
# the same class of apt/dpkg invocation and carries the same risks.
fix_output_file="$(mktemp)"
timeout "${APT_CALL_TIMEOUT}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    apt-get --fix-broken install -y \
    -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    < /dev/null > "${fix_output_file}" 2>&1
fix_status=$?
fix_output="$(cat "${fix_output_file}")"
rm -f "${fix_output_file}"
 
if [[ "${fix_status}" -eq 124 ]]; then
    add_action "apt-get --fix-broken install" "FAILED" "timed out after ${APT_CALL_TIMEOUT}s"
elif [[ "${fix_status}" -eq 0 ]]; then
    add_action "apt-get --fix-broken install" "OK" "$(tail -n 5 <<< "${fix_output}")"
else
    add_action "apt-get --fix-broken install" "FAILED" "exit ${fix_status}: $(tail -n 10 <<< "${fix_output}")"
fi
 
# --- 3d. Re-run dpkg --audit, confirm empty ---
FINAL_AUDIT_OUTPUT="$(dpkg --audit 2>/dev/null || true)"
mapfile -t FINAL_AUDIT_PACKAGES < <(grep -oP '^ \K\S+' <<< "${FINAL_AUDIT_OUTPUT}" | sort -u)
 
if [[ "${#FINAL_AUDIT_PACKAGES[@]}" -eq 0 ]]; then
    add_action "dpkg --audit (re-run)" "OK" "clean"
    recovered="true"
else
    add_action "dpkg --audit (re-run)" "FAILED" "still broken: $(IFS=,; echo "${FINAL_AUDIT_PACKAGES[*]}")"
    recovered="false"
fi
 
# ---------------------------------------------------------------------------
# 4. Restart affected services (only if recovery succeeded - restarting
#    services on top of a still-broken package state would just add a
#    second failure mode on top of the first).
# ---------------------------------------------------------------------------
RESTART_RESULTS=()
if [[ "${recovered}" == "true" && -f "${SVC_MAP_PATH}" ]] && jq empty "${SVC_MAP_PATH}" >/dev/null 2>&1; then
    echo "[*] Restarting affected services..."
    mapfile -t AFFECTED_SERVICES < <(jq -r --argjson broken "${BROKEN_PKGS_JSON}" '
        .services[]? | select(.owning_package as $o | ($broken | index($o)) != null or (.linked_packages | any(. as $lp | $broken | index($lp) != null))) | .service
    ' "${SVC_MAP_PATH}" 2>/dev/null | sort -u)
 
    for svc in "${AFFECTED_SERVICES[@]}"; do
        [[ -z "${svc}" ]] && continue
        if systemctl restart "${svc}" >/dev/null 2>&1; then
            state="$(systemctl show -p ActiveState --value "${svc}" 2>/dev/null || echo unknown)"
            printf '    %-38s %s\n' "${svc}" "${state}"
            RESTART_RESULTS+=("$(jq -n --arg s "${svc}" --arg st "${state}" '{service: $s, result: "OK", active_state: $st}')")
        else
            printf '    %-38s FAILED\n' "${svc}"
            RESTART_RESULTS+=("$(jq -n --arg s "${svc}" '{service: $s, result: "FAILED", active_state: null}')")
        fi
    done
fi
RESTARTS_JSON="[$(IFS=,; echo "${RESTART_RESULTS[*]:-}")]"
 
end_ts="$(date -u +%s.%N)"
duration_seconds="$(awk -v a="${start_ts}" -v b="${end_ts}" 'BEGIN { printf "%.0f", b - a }')"
 
echo "RECOVERED: $( [[ "${recovered}" == "true" ]] && echo yes || echo no )"
echo "Duration: ${duration_seconds}s"
 
# ---------------------------------------------------------------------------
# 5. Write report
# ---------------------------------------------------------------------------
ACTIONS_JSON="[$(IFS=,; echo "${ACTIONS[*]:-}")]"
 
FINAL_AUDIT_PKGS_JSON="[$(for p in "${FINAL_AUDIT_PACKAGES[@]}"; do [[ -n "${p}" ]] && printf '"%s",' "$(json_escape "${p}")"; done | sed 's/,$//')]"
 
FINAL_STATE=$(jq -n \
    --arg audit_raw "${FINAL_AUDIT_OUTPUT}" \
    --argjson remaining "${FINAL_AUDIT_PKGS_JSON}" \
    --argjson restarts "${RESTARTS_JSON}" \
    '{dpkg_audit_raw: $audit_raw, remaining_broken_packages: $remaining, service_restarts: $restarts}')
 
jq -n \
    --argjson diag "${INITIAL_DIAGNOSIS}" \
    --argjson actions "${ACTIONS_JSON}" \
    --argjson final "${FINAL_STATE}" \
    --argjson recovered "${recovered}" \
    --argjson duration "${duration_seconds}" \
    '{initial_diagnosis: $diag, actions_taken: $actions, final_state: $final, recovered: $recovered, duration_seconds: $duration, refused: false}' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
 
if [[ "${recovered}" == "true" ]]; then
    exit 0
else
    exit 1
fi
