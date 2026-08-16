#!/bin/bash
#
# script name : 0-network_baseline.sh
# purpose     : discover the current network topology from this hardened
#               endpoint's own perspective and capture it as a structured
#               baseline - active interfaces, routing table, ARP
#               neighbors, listening sockets, established connections and
#               DNS resolver configuration - so every later firewall rule
#               and network-security decision can be justified against
#               real, captured evidence rather than opinion. Pure
#               read-only measurement - never changes network state.
# author      : Aïda Sylla
# date        : 2026-08-16
 
set -uo pipefail
# NOTE: deliberately not using -e. A missing systemd-resolved, an ss
# version without JSON support, or zero established connections at the
# moment of capture are all expected, legitimate states this script must
# still record faithfully - not script bugs.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "Warning: not running as root. Some socket-to-process resolution (ss -p) and route/neighbor visibility may be incomplete without full privileges. Try: sudo $0" >&2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to assemble network_baseline.json. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "ip (iproute2) not found. This script requires it to read interfaces, routes and neighbors." >&2
    exit 1
fi
if ! command -v ss >/dev/null 2>&1; then
    echo "ss (iproute2) not found. This script requires it to read listening and established sockets." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${SCRIPT_DIR}/network_baseline.json"
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
echo "[*] Capturing network baseline..."
 
# ---------------------------------------------------------------------------
# 1. Interfaces: name, MAC, link state, all assigned addresses.
#    ip -j addr show already emits well-formed JSON on any reasonably
#    recent iproute2 - reshaped here into a stable, minimal schema rather
#    than passed through as-is, so later tasks don't depend on iproute2's
#    own internal field names changing between versions.
# ---------------------------------------------------------------------------
echo "    interfaces..."
IP_ADDR_RAW="$(ip -j addr show 2>/dev/null || echo '[]')"
if ! jq -e . >/dev/null 2>&1 <<< "${IP_ADDR_RAW}"; then
    IP_ADDR_RAW='[]'
fi
INTERFACES_JSON="$(jq -c '[.[] | {
    name: .ifname,
    mac: (.address // null),
    state: .operstate,
    addresses: [ (.addr_info // [])[] | {family: .family, address: .local, prefixlen: .prefixlen} ]
}]' <<< "${IP_ADDR_RAW}")"
 
up_interfaces_count="$(jq '[.[] | select(.state == "UP")] | length' <<< "${INTERFACES_JSON}")"
 
# ---------------------------------------------------------------------------
# 2. Routing table, including the default gateway.
# ---------------------------------------------------------------------------
echo "    routes..."
IP_ROUTE_RAW="$(ip -j route show 2>/dev/null || echo '[]')"
if ! jq -e . >/dev/null 2>&1 <<< "${IP_ROUTE_RAW}"; then
    IP_ROUTE_RAW='[]'
fi
ROUTES_JSON="$(jq -c '[.[] | {
    destination: .dst,
    gateway: (.gateway // null),
    device: (.dev // null),
    protocol: (.protocol // null),
    metric: (.metric // null)
}]' <<< "${IP_ROUTE_RAW}")"
 
# ---------------------------------------------------------------------------
# 3. ARP neighbors table.
# ---------------------------------------------------------------------------
echo "    neighbors..."
IP_NEIGH_RAW="$(ip -j neigh show 2>/dev/null || echo '[]')"
if ! jq -e . >/dev/null 2>&1 <<< "${IP_NEIGH_RAW}"; then
    IP_NEIGH_RAW='[]'
fi
NEIGHBORS_JSON="$(jq -c '[.[] | {
    ip: .dst,
    mac: (.lladdr // null),
    device: (.dev // null),
    state: ((.state // []) | join(","))
}]' <<< "${IP_NEIGH_RAW}")"
 
# ---------------------------------------------------------------------------
# 4/5. Listening and established sockets.
#    NOTE: `ss -j`/`ss --json` support and its exact field schema vary
#    across iproute2 versions - genuinely unverified at the time this
#    script was written. A JSON attempt is made first; if it doesn't
#    produce valid, non-empty JSON, this falls back to parsing the
#    classic `-H` (no header) plain-text output instead, which is the
#    long-stable, well-documented format this parser is built around and
#    tested against. Multi-process sockets (a port shared by several
#    worker processes) are handled by keeping only the FIRST pid= match -
#    without this, multiple matched PIDs get joined by a space by command
#    substitution, producing an invalid JSON numeric literal downstream
#    (the exact failure mode found the hard way on a real multi-worker
#    apache2 in an earlier module).
# ---------------------------------------------------------------------------
parse_ss_line_to_json() {
    local line="$1" include_remote="$2"
    local proto local_addr remote_addr proc_info proc_name pid
 
    proto="$(awk '{print $1}' <<< "${line}")"
    if [[ "${include_remote}" == "true" ]]; then
        local_addr="$(awk '{print $5}' <<< "${line}")"
        remote_addr="$(awk '{print $6}' <<< "${line}")"
    else
        local_addr="$(awk '{print $5}' <<< "${line}")"
        remote_addr=""
    fi
 
    proc_info="$(grep -oP 'users:\(\(\K[^)]*' <<< "${line}" || true)"
    proc_name="$(grep -oP '^"?\K[^",]*' <<< "${proc_info}" || true)"
    pid="$(grep -oP 'pid=\K[0-9]+' <<< "${proc_info}" | head -1 || true)"
    [[ -z "${pid}" ]] && pid="0"
 
    if [[ "${include_remote}" == "true" ]]; then
        printf '{"protocol":"%s","local_address":"%s","remote_address":"%s","process":"%s","pid":%s}' \
            "$(json_escape "${proto}")" "$(json_escape "${local_addr}")" "$(json_escape "${remote_addr}")" \
            "$(json_escape "${proc_name}")" "${pid}"
    else
        printf '{"protocol":"%s","local_address":"%s","process":"%s","pid":%s}' \
            "$(json_escape "${proto}")" "$(json_escape "${local_addr}")" \
            "$(json_escape "${proc_name}")" "${pid}"
    fi
}
 
echo "    listening sockets..."
LISTEN_ENTRIES=()
SS_LISTEN_JSON_RAW="$(ss -tulnp --json 2>/dev/null || true)"
if [[ -n "${SS_LISTEN_JSON_RAW}" ]] && jq -e '. | type == "array" and length > 0' >/dev/null 2>&1 <<< "${SS_LISTEN_JSON_RAW}"; then
    LISTENING_SOCKETS_JSON="$(jq -c '[.[] | {
        protocol: (."protocol" // "unknown"),
        local_address: ((."local-address" // "") + ":" + (."local-port" // "" | tostring)),
        process: ((.process[0].name) // ""),
        pid: ((.process[0].pid) // 0)
    }]' <<< "${SS_LISTEN_JSON_RAW}" 2>/dev/null || echo '[]')"
else
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        LISTEN_ENTRIES+=("$(parse_ss_line_to_json "${line}" "false")")
    done < <(ss -tulnpH 2>/dev/null || true)
    LISTENING_SOCKETS_JSON="[$(IFS=,; echo "${LISTEN_ENTRIES[*]:-}")]"
fi
listener_count="$(jq 'length' <<< "${LISTENING_SOCKETS_JSON}")"
 
echo "    established connections..."
ESTAB_ENTRIES=()
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    ESTAB_ENTRIES+=("$(parse_ss_line_to_json "${line}" "true")")
done < <(ss -tnpH state established 2>/dev/null || true)
ESTABLISHED_JSON="[$(IFS=,; echo "${ESTAB_ENTRIES[*]:-}")]"
 
# ---------------------------------------------------------------------------
# 6. DNS resolver configuration.
# ---------------------------------------------------------------------------
echo "    dns resolvers..."
mapfile -t RESOLV_NAMESERVERS < <(grep -E '^nameserver[[:space:]]' /etc/resolv.conf 2>/dev/null | awk '{print $2}')
NAMESERVERS_JSON="[$(for ns in "${RESOLV_NAMESERVERS[@]}"; do printf '"%s",' "$(json_escape "${ns}")"; done | sed 's/,$//')]"
 
resolvectl_status="null"
if command -v resolvectl >/dev/null 2>&1 && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    resolvectl_raw="$(resolvectl status --no-pager 2>/dev/null || true)"
    if [[ -n "${resolvectl_raw}" ]]; then
        resolvectl_status="$(jq -Rs '.' <<< "${resolvectl_raw}")"
    fi
fi
 
DNS_JSON="$(jq -n --argjson nameservers "${NAMESERVERS_JSON}" --argjson resolvectl "${resolvectl_status}" \
    '{resolv_conf_nameservers: $nameservers, systemd_resolved_active: ($resolvectl != null), resolvectl_status: $resolvectl}')"
 
# ---------------------------------------------------------------------------
# 7. Emit network_baseline.json
# ---------------------------------------------------------------------------
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson interfaces "${INTERFACES_JSON}" \
    --argjson routes "${ROUTES_JSON}" \
    --argjson neighbors "${NEIGHBORS_JSON}" \
    --argjson listening_sockets "${LISTENING_SOCKETS_JSON}" \
    --argjson established_connections "${ESTABLISHED_JSON}" \
    --argjson dns_resolvers "${DNS_JSON}" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        interfaces: $interfaces,
        routes: $routes,
        neighbors: $neighbors,
        listening_sockets: $listening_sockets,
        established_connections: $established_connections,
        dns_resolvers: $dns_resolvers
    }' > "${OUTPUT_PATH}"
 
echo "Interfaces up: ${up_interfaces_count}   Listeners: ${listener_count}"
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
exit 0
