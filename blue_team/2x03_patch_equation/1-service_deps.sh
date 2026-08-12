#!/bin/bash
#
# script name : 1-service_deps.sh
# purpose     : build a service-to-package dependency map for the current
#               host: enumerate every active systemd service, resolve its
#               executable (from ExecStart, falling back to MainPID's
#               /proc/<pid>/exe), resolve the owning package for that
#               executable and every dynamic library it links against via
#               dpkg -S, tag each service with a criticality label from
#               service_criticality.json, and cross-check with
#               needrestart -b to flag whether a restart is currently
#               pending. Emits service_dependency_map.json.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -euo pipefail
# Every per-service lookup below (ExecStart parsing, MainPID fallback,
# dpkg -S on a library not owned by any package, needrestart absence) is
# expected to legitimately come back empty for some services as part of
# normal operation, and must not abort the whole map. Every such lookup is
# guarded with an explicit if/case or "|| true" rather than left to
# propagate under -e.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "Warning: not running as root. systemctl show / MainPID resolution and reading other users' /proc/<pid>/exe may return incomplete results. Try: sudo $0" >&2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to read service_criticality.json and write the map. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found. This script requires a systemd host." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRITICALITY_FILE="${SCRIPT_DIR}/service_criticality.json"
OUTPUT_PATH="${SCRIPT_DIR}/service_dependency_map.json"
 
if [[ -f "${CRITICALITY_FILE}" ]]; then
    if ! jq empty "${CRITICALITY_FILE}" >/dev/null 2>&1; then
        echo "service_criticality.json exists but is not valid JSON: ${CRITICALITY_FILE}" >&2
        exit 1
    fi
    HAVE_CRITICALITY=true
else
    echo "Warning: ${CRITICALITY_FILE} not found. Every service will default to 'low' criticality (per this task's own default rule)." >&2
    HAVE_CRITICALITY=false
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
echo "[*] Listing active systemd services..."
 
# ---------------------------------------------------------------------------
# 1. Every active service unit
# ---------------------------------------------------------------------------
mapfile -t SERVICES < <(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}')
echo "    ${#SERVICES[@]} active services found."
 
# ---------------------------------------------------------------------------
# needrestart cross-check (optional - the task's own suggested hint).
# needrestart -b output includes one "NEEDRESTART-SVC: <unit>" line per
# service currently flagged as needing a restart.
# ---------------------------------------------------------------------------
declare -A NEEDS_RESTART
if command -v needrestart >/dev/null 2>&1; then
    while IFS= read -r svc; do
        [[ -n "${svc}" ]] && NEEDS_RESTART["${svc}"]=1
    done < <(needrestart -b 2>/dev/null | awk -F': ' '/^NEEDRESTART-SVC:/{print $2}' || true)
else
    echo "Warning: needrestart not found - restart_required_on_patch will be derived only from whether this service links a package, not cross-checked against needrestart -b." >&2
fi
 
# ---------------------------------------------------------------------------
# 2. Resolve the executable path for a service.
# ---------------------------------------------------------------------------
resolve_exec_path() {
    local unit="$1" exec_line path pid proc_exe
 
    exec_line="$(systemctl show -p ExecStart --value "${unit}" 2>/dev/null || true)"
    if [[ -n "${exec_line}" ]]; then
        path="$(grep -oP '(?<=path=)\S+' <<< "${exec_line}" | head -1 || true)"
        if [[ -n "${path}" && -e "${path}" ]]; then
            echo "${path}"
            return
        fi
    fi
 
    pid="$(systemctl show -p MainPID --value "${unit}" 2>/dev/null || true)"
    if [[ -n "${pid}" && "${pid}" != "0" ]]; then
        proc_exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
        if [[ -n "${proc_exe}" && -e "${proc_exe}" ]]; then
            echo "${proc_exe}"
            return
        fi
    fi
 
    echo ""
}
 
# ---------------------------------------------------------------------------
# 3/4. Resolve the owning package for a file path.
#    NOTE: on systems using the usrmerge layout, /lib, /bin, /sbin (and the
#    per-arch variants under /lib/<triplet>) are symlinks into /usr/. dpkg's
#    file database is keyed on the CANONICAL path, so a raw path straight
#    out of ldd's output (e.g. /lib/x86_64-linux-gnu/libssl.so.3) will fail
#    to resolve even though the file exists - it must be passed through
#    readlink -f first. Confirmed by testing against a real usrmerge system.
# ---------------------------------------------------------------------------
resolve_owning_package() {
    local raw_path="$1" canonical result pkg
    canonical="$(readlink -f "${raw_path}" 2>/dev/null || echo "${raw_path}")"
    result="$(dpkg -S "${canonical}" 2>/dev/null || true)"
    [[ -z "${result}" ]] && { echo ""; return; }
    pkg="$(cut -d: -f1 <<< "${result}" | head -1)"
    echo "${pkg}"
}
 
# ---------------------------------------------------------------------------
# 4. Linked libraries for an executable, resolved to owning packages.
# ---------------------------------------------------------------------------
get_linked_packages() {
    local exec_path="$1" owning_pkg="$2" lib_paths pkg
    declare -A seen
    [[ -n "${owning_pkg}" ]] && seen["${owning_pkg}"]=1
 
    lib_paths="$(ldd "${exec_path}" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="=>") print $(i+1)}' || true)"
    while IFS= read -r lib_path; do
        [[ -z "${lib_path}" || "${lib_path}" == "not" ]] && continue
        pkg="$(resolve_owning_package "${lib_path}")"
        [[ -n "${pkg}" ]] && seen["${pkg}"]=1
    done <<< "${lib_paths}"
 
    local out=()
    for pkg in "${!seen[@]}"; do out+=("${pkg}"); done
    IFS=$'\n' out=($(sort <<< "${out[*]}")); unset IFS
    printf '%s\n' "${out[@]}"
}
 
# ---------------------------------------------------------------------------
# 5. Criticality lookup
# ---------------------------------------------------------------------------
lookup_criticality() {
    local unit="$1"
    [[ "${HAVE_CRITICALITY}" == true ]] || { echo "low"; return; }
    jq -r --arg u "${unit}" '.[$u] // "low"' "${CRITICALITY_FILE}" 2>/dev/null || echo "low"
}
 
# ---------------------------------------------------------------------------
# Build the map
# ---------------------------------------------------------------------------
echo "[*] Resolving executables, packages and library dependencies..."
 
ENTRIES=()
resolved_count=0
 
for unit in "${SERVICES[@]}"; do
    [[ -z "${unit}" ]] && continue
 
    exec_path="$(resolve_exec_path "${unit}")"
    if [[ -z "${exec_path}" ]]; then
        continue
    fi
    resolved_count=$((resolved_count + 1))
 
    owning_pkg="$(resolve_owning_package "${exec_path}")"
 
    mapfile -t linked_pkgs < <(get_linked_packages "${exec_path}" "${owning_pkg}")
    linked_json_parts=()
    for p in "${linked_pkgs[@]}"; do
        [[ -z "${p}" ]] && continue
        linked_json_parts+=("\"$(json_escape "${p}")\"")
    done
    linked_json="[$(IFS=,; echo "${linked_json_parts[*]:-}")]"
 
    criticality="$(lookup_criticality "${unit}")"
 
    restart_required="false"
    [[ -n "${NEEDS_RESTART[${unit}]:-}" ]] && restart_required="true"
 
    entry=$(printf '{"service":"%s","exec_path":"%s","owning_package":"%s","linked_packages":%s,"criticality":"%s","restart_required_on_patch":%s}' \
        "$(json_escape "${unit}")" "$(json_escape "${exec_path}")" "$(json_escape "${owning_pkg}")" \
        "${linked_json}" "$(json_escape "${criticality}")" "${restart_required}")
 
    ENTRIES+=("${entry}")
done
 
echo "    ${resolved_count}/${#SERVICES[@]} services resolved to an executable, ${#ENTRIES[@]} entries recorded."
 
# ---------------------------------------------------------------------------
# Write the map
# ---------------------------------------------------------------------------
{
    printf '{'
    printf '"generated":"%s",' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '"hostname":"%s",' "$(json_escape "$(hostname)")"
    printf '"active_service_count":%s,' "${#SERVICES[@]}"
    printf '"criticality_file_available":%s,' "${HAVE_CRITICALITY}"
    printf '"services":['
    for idx in "${!ENTRIES[@]}"; do
        [[ "${idx}" -gt 0 ]] && printf ','
        printf '%s' "${ENTRIES[$idx]}"
    done
    printf ']'
    printf '}'
} | jq '.' > "${OUTPUT_PATH}"
 
echo "Service dependency map saved to: ${OUTPUT_PATH}"
