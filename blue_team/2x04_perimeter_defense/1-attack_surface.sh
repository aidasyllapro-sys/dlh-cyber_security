#!/bin/bash
#
# script name : 1-attack_surface.sh
# purpose     : classify every listening socket captured in
#               network_baseline.json (Task 0) into a machine-readable
#               attack surface report - resolving each socket's owning
#               binary, package (dpkg -S) and systemd unit, tagging it
#               with a function and a criticality from two project
#               catalogs, and flagging every socket that matches a
#               "should not be exposed" rule (a database/rpc service
#               bound to all interfaces, or any inherently insecure
#               protocol such as telnet/ftp/snmpv1/snmpv2c/rlogin/NFSv2-3).
#               This is the input T2's zone design will read. Pure
#               read-only classification - never changes network state.
# author      : Aïda Sylla
# date        : 2026-08-16
 
set -uo pipefail
# NOTE: deliberately not using -e. A socket with no resolvable package, no
# matching systemd unit, or an unknown function are all expected,
# legitimate outcomes this script exists to report (and explicitly count
# separately, per the task's own note) - not script bugs.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "Warning: not running as root. /proc/<pid>/exe resolution and systemctl status <pid> may be incomplete for sockets owned by other users. Try: sudo $0" >&2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_PATH="${SCRIPT_DIR}/network_baseline.json"
CATALOG_PATH="${SCRIPT_DIR}/service_catalog.json"
CRITICALITY_PATH="${SCRIPT_DIR}/service_criticality.json"
OUTPUT_PATH="${SCRIPT_DIR}/attack_surface.json"
 
if [[ ! -f "${BASELINE_PATH}" ]]; then
    echo "network_baseline.json not found at ${BASELINE_PATH}. Run 0-network_baseline.sh first." >&2
    exit 1
fi
if ! jq empty "${BASELINE_PATH}" >/dev/null 2>&1; then
    echo "network_baseline.json is not valid JSON: ${BASELINE_PATH}" >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# service_catalog.json / service_criticality.json are project-supplied
# fixtures the task references but does not define a schema for.
# Assumed schema (documented here, adjust if the project supplies a
# different one):
#   service_catalog.json:      { "<port>": "<function>", ... }  - keyed by
#     port number as a string, since the port is the unambiguous
#     attack-surface identifier (process names vary by distro/build).
#     Falls back to a lookup by process name if the port isn't listed.
#     Function values are NOT restricted to the task's own point-3 example
#     list (database, web, ssh, dns, ntp, rpc, smb, print, telemetry,
#     unknown) - point 5's flagging rule references finer-grained protocol
#     functions (telnet, ftp, snmpv1, snmpv2c, rlogin, "nfs v2/v3") that
#     never appear in that example list, so the catalog must be free-form.
#   service_criticality.json:  { "<process-name>": "<criticality>", ... }
#     criticality in {critical, high, medium, low}; unset -> "low",
#     mirroring this project's earlier module's own hold/criticality
#     lookup convention.
# ---------------------------------------------------------------------------
HAVE_CATALOG=false
if [[ -f "${CATALOG_PATH}" ]] && jq empty "${CATALOG_PATH}" >/dev/null 2>&1; then
    HAVE_CATALOG=true
else
    echo "Warning: service_catalog.json not found or invalid - every socket's function will default to 'unknown'." >&2
fi
 
HAVE_CRITICALITY=false
if [[ -f "${CRITICALITY_PATH}" ]] && jq empty "${CRITICALITY_PATH}" >/dev/null 2>&1; then
    HAVE_CRITICALITY=true
else
    echo "Warning: service_criticality.json not found or invalid - every socket's criticality will default to 'low'." >&2
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
# usrmerge-aware dpkg -S resolution (same lesson learned the hard way in
# an earlier module: this system's dpkg database is inconsistently keyed
# between a binary's raw path and its canonical /usr-merged path,
# depending on the package - try both).
resolve_owning_package() {
    local raw_path="$1" canonical result
    [[ -z "${raw_path}" ]] && { echo ""; return; }
    result="$(dpkg -S "${raw_path}" 2>/dev/null || true)"
    if [[ -z "${result}" ]]; then
        canonical="$(readlink -f "${raw_path}" 2>/dev/null || true)"
        if [[ -n "${canonical}" && "${canonical}" != "${raw_path}" ]]; then
            result="$(dpkg -S "${canonical}" 2>/dev/null || true)"
        fi
    fi
    [[ -z "${result}" ]] && { echo ""; return; }
    cut -d: -f1 <<< "${result}" | head -1
}
 
resolve_binary_path() {
    local pid="$1"
    [[ -z "${pid}" || "${pid}" == "0" ]] && { echo ""; return; }
    readlink -f "/proc/${pid}/exe" 2>/dev/null || echo ""
}
 
# Resolve a PID to its owning systemd unit, if any, via systemctl's own
# pid-to-unit lookup (its header line: "* unit.service - Description").
resolve_systemd_unit() {
    local pid="$1" status_out unit
    [[ -z "${pid}" || "${pid}" == "0" ]] && { echo ""; return; }
    command -v systemctl >/dev/null 2>&1 || { echo ""; return; }
    status_out="$(systemctl status "${pid}" --no-pager 2>/dev/null || true)"
    [[ -z "${status_out}" ]] && { echo ""; return; }
    unit="$(head -1 <<< "${status_out}" | grep -oP '\S+\.service(?=\s|$)' | head -1 || true)"
    echo "${unit}"
}
 
lookup_function() {
    local port="$1" process="$2" fn
    if [[ "${HAVE_CATALOG}" != true ]]; then
        echo "unknown"; return
    fi
    fn="$(jq -r --arg p "${port}" '.[$p] // empty' "${CATALOG_PATH}" 2>/dev/null || true)"
    if [[ -z "${fn}" ]]; then
        fn="$(jq -r --arg p "${process}" '.[$p] // empty' "${CATALOG_PATH}" 2>/dev/null || true)"
    fi
    [[ -z "${fn}" ]] && fn="unknown"
    echo "${fn}"
}
 
lookup_criticality() {
    local process="$1" crit
    if [[ "${HAVE_CRITICALITY}" != true ]]; then
        echo "low"; return
    fi
    crit="$(jq -r --arg p "${process}" '.[$p] // "low"' "${CRITICALITY_PATH}" 2>/dev/null || echo "low")"
    echo "${crit}"
}
 
# ---------------------------------------------------------------------------
# 5. "Should not be exposed" rules.
# ---------------------------------------------------------------------------
is_bound_all_interfaces() {
    local bind_addr="$1"
    [[ "${bind_addr}" == "0.0.0.0" || "${bind_addr}" == "*" || "${bind_addr}" == "::" ]]
}
 
compute_exposure_flags() {
    local bind_addr="$1" function="$2" flags=()
 
    # Per the task's own rule: "bound to 0.0.0.0 ON A SERVICE TAGGED
    # database OR rpc" - the all-interfaces bind only matters, and is
    # only flagged, when it's paired with one of those two functions. A
    # 0.0.0.0-bound socket with an unrelated or unknown function is NOT
    # flagged by this rule alone (found the hard way: an earlier version
    # of this function flagged bound_0.0.0.0 unconditionally for ANY
    # all-interfaces bind, which silently over-flagged every unrelated
    # service just for listening broadly).
    if is_bound_all_interfaces "${bind_addr}"; then
        case "${function}" in
            database) flags+=("bound_0.0.0.0" "database_exposed") ;;
            rpc)      flags+=("bound_0.0.0.0" "rpc_exposed") ;;
        esac
    fi
 
    case "${function}" in
        telnet|ftp|snmpv1|snmpv2c|rlogin|"nfs v2/v3"|nfsv2|nfsv3)
            flags+=("insecure_protocol_${function// /_}")
            ;;
    esac
 
    printf '%s\n' "${flags[@]}"
}
 
echo "[*] Classifying listening sockets from network_baseline.json..."
 
SOCKETS_JSON_ENTRIES=()
flagged_critical=0
flagged_high=0
flagged_medium=0
flagged_low=0
unknown_function_count=0
total_flagged=0
 
mapfile -t SOCKET_LINES < <(jq -c '.listening_sockets[]?' "${BASELINE_PATH}")
socket_count="${#SOCKET_LINES[@]}"
echo "    ${socket_count} listening sockets to classify."
 
for entry in "${SOCKET_LINES[@]}"; do
    proto="$(jq -r '.protocol' <<< "${entry}")"
    local_address="$(jq -r '.local_address' <<< "${entry}")"
    process="$(jq -r '.process' <<< "${entry}")"
    pid="$(jq -r '.pid' <<< "${entry}")"
 
    # local_address is "bind:port" (IPv4) or can include a scope like
    # "127.0.0.53%lo:53" - split on the LAST colon so IPv6-style or
    # scoped addresses with embedded colons don't break the port split.
    bind_addr="${local_address%:*}"
    port="${local_address##*:}"
 
    binary_path="$(resolve_binary_path "${pid}")"
    package="$(resolve_owning_package "${binary_path}")"
    systemd_unit="$(resolve_systemd_unit "${pid}")"
 
    function_label="$(lookup_function "${port}" "${process}")"
    criticality="$(lookup_criticality "${process}")"
    [[ "${function_label}" == "unknown" ]] && unknown_function_count=$((unknown_function_count + 1))
 
    mapfile -t flags < <(compute_exposure_flags "${bind_addr}" "${function_label}")
    flags_clean=()
    for f in "${flags[@]}"; do [[ -n "${f}" ]] && flags_clean+=("${f}"); done
 
    if [[ "${#flags_clean[@]}" -gt 0 ]]; then
        total_flagged=$((total_flagged + 1))
        case "${criticality}" in
            critical) flagged_critical=$((flagged_critical + 1)) ;;
            high)     flagged_high=$((flagged_high + 1)) ;;
            medium)   flagged_medium=$((flagged_medium + 1)) ;;
            *)        flagged_low=$((flagged_low + 1)) ;;
        esac
    fi
 
    flags_json="[$(for f in "${flags_clean[@]}"; do printf '"%s",' "$(json_escape "${f}")"; done | sed 's/,$//')]"
 
    socket_entry=$(jq -n \
        --arg proto "${proto}" --argjson port "${port:-0}" --arg bind_addr "${bind_addr}" \
        --arg process "${process}" --arg package "${package}" --arg unit "${systemd_unit}" \
        --arg function "${function_label}" --arg criticality "${criticality}" \
        --argjson flags "${flags_json}" \
        '{proto: $proto, port: $port, bind_addr: $bind_addr, process: $process,
          package: $package, systemd_unit: $unit, function: $function,
          criticality: $criticality, exposure_flags: $flags}')
    SOCKETS_JSON_ENTRIES+=("${socket_entry}")
done
 
echo "Flagged sockets: ${total_flagged}   (critical=${flagged_critical} high=${flagged_high} medium=${flagged_medium} low=${flagged_low})"
echo "Unknown function: ${unknown_function_count}"
 
SOCKETS_JSON="[$(IFS=,; echo "${SOCKETS_JSON_ENTRIES[*]:-}")]"
 
jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson sockets "${SOCKETS_JSON}" \
    --argjson total_flagged "${total_flagged}" \
    --argjson flagged_critical "${flagged_critical}" \
    --argjson flagged_high "${flagged_high}" \
    --argjson flagged_medium "${flagged_medium}" \
    --argjson flagged_low "${flagged_low}" \
    --argjson unknown_function "${unknown_function_count}" \
    --argjson total_sockets "${socket_count}" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        sockets: $sockets,
        summary: {
            total_sockets: $total_sockets,
            total_flagged: $total_flagged,
            flagged_by_severity: { critical: $flagged_critical, high: $flagged_high, medium: $flagged_medium, low: $flagged_low },
            unknown_function: $unknown_function
        }
    }' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
exit 0
