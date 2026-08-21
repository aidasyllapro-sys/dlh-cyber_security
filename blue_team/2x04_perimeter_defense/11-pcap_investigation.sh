#!/bin/bash
#
# script name : 11-pcap_investigation.sh
# purpose     : investigate a suspicious PCAP with tshark - extract the
#               conversation timeline (TCP/UDP), DNS queries, HTTP
#               requests, TLS SNI, file-transfer indicators and the
#               protocol hierarchy, exactly what a Tier 2 analyst does
#               after a Suricata alert points at a session: open the
#               capture, walk the protocol stack, characterize the
#               activity by bytes, not by signature. No alert, no
#               ruleset - this script is pure packet-level investigation.
# author      : Aïda Sylla
# date        : 2026-08-18
#
# NOT YET VALIDATED AGAINST REAL TSHARK OUTPUT: this script was written
# in an environment with no tshark available and no network to install
# it. `tshark -q -z conv,tcp/udp` and `-z io,phs` produce specific
# tabular/tree text formats that are well-documented but genuinely vary
# in exact spacing across tshark/Wireshark versions - the parsing logic
# below is my best-effort against the documented format and WILL likely
# need live adjustment against the real tshark installed on billing-srv-01,
# the same way 8-suricata_setup.sh's suricata.yaml needed real fixes
# against real suricata 6.0.4. Every parse step degrades to an empty
# array rather than crashing if its expected format isn't matched,
# per this task's own resilience requirement - but "gracefully empty"
# is not the same as "correctly parsed," and that gap needs a real test.
 
set -uo pipefail
# NOTE: deliberately not using -e. Zero conversations, zero DNS queries,
# or any other empty-result case are expected, meaningful outcomes this
# script must report as empty arrays, not treat as failures.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (tshark needs to read the PCAP). Try: sudo $0" >&2
    exit 1
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
if ! command -v tshark >/dev/null 2>&1; then
    echo "tshark not found. Install it (e.g. apt install tshark) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${SCRIPT_DIR}/pcap_findings.json"
 
# 1. Accept a PCAP path as argument, default to the project's suspicious
#    session capture.
PCAP_PATH="${1:-/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap}"
 
if [[ ! -f "${PCAP_PATH}" ]]; then
    echo "PCAP not found at ${PCAP_PATH}." >&2
    exit 1
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
echo "[*] PCAP: ${PCAP_PATH}"
 
# ---------------------------------------------------------------------------
# Duration / packet count, via capinfos (ships alongside tshark in the
# wireshark-common package) - simpler and more reliable to parse than
# deriving these from a tshark statistics tree.
# ---------------------------------------------------------------------------
duration="0"
packet_count="0"
if command -v capinfos >/dev/null 2>&1; then
    capinfos_out="$(capinfos -c -u "${PCAP_PATH}" 2>/dev/null || true)"
    packet_count="$(grep -oP 'Number of packets:\s*\K[0-9,]+' <<< "${capinfos_out}" | tr -d ',' || echo 0)"
    duration="$(grep -oP 'Capture duration:\s*\K[0-9.]+' <<< "${capinfos_out}" || echo 0)"
fi
[[ -z "${packet_count}" ]] && packet_count=0
[[ -z "${duration}" ]] && duration=0
 
printf "[*] Duration: %s s     Packets: %s\n" "${duration}" "${packet_count}"
 
# ---------------------------------------------------------------------------
# Conversations (TCP/UDP). tshark's `-z conv,<proto>` output is a
# pipe-delimited table (recent tshark/Wireshark versions); each data row
# is parsed with a tolerant regex, and any row this parser cannot
# confidently read is silently skipped rather than corrupting the report -
# this is the single most likely piece of this script to need a real
# format adjustment once tested against billing-srv-01's actual tshark.
# ---------------------------------------------------------------------------
parse_conversations() {
    local proto="$1"
    local raw
    raw="$(tshark -r "${PCAP_PATH}" -q -z "conv,${proto}" 2>/dev/null || true)"
 
    local entries=()
    while IFS= read -r line; do
        # Expect a data row shaped like:
        #   addrA:portA <-> addrB:portB   framesAB bytesAB   framesBA bytesBA   framesTotal bytesTotal   ...
        if [[ "${line}" =~ ^([0-9A-Fa-f.:]+):?([0-9]*)[[:space:]]*\<-\>[[:space:]]*([0-9A-Fa-f.:]+):?([0-9]*)[[:space:]]*\|?[[:space:]]*([0-9]+)[[:space:]]+([0-9.,]+[[:space:]]*[kKmMgG]?[bB]?y?t?e?s?)[[:space:]]*\|?[[:space:]]*([0-9]+)[[:space:]]+([0-9.,]+[[:space:]]*[kKmMgG]?[bB]?y?t?e?s?)[[:space:]]*\|?[[:space:]]*([0-9]+)[[:space:]]+([0-9.,]+[[:space:]]*[kKmMgG]?[bB]?y?t?e?s?) ]]; then
            # NOTE: confirmed against real tshark 3.6.2 output on
            # billing-srv-01 - group 1/3 greedily capture the port along
            # with the address (both digits and ":" are in the same
            # character class), since real tshark separates address from
            # port with a bare ":" and no distinguishing delimiter this
            # regex alone can key off. The task's own expected output
            # shows bare IPs without ports in the conversation summary,
            # so the port is stripped back out here via simple parameter
            # expansion on the last ":" rather than a more fragile regex.
            local addr_a="${BASH_REMATCH[1]%:*}"
            local addr_b="${BASH_REMATCH[3]%:*}"
            local total_packets="${BASH_REMATCH[9]}"
            local total_bytes="${BASH_REMATCH[10]}"
            entries+=("$(jq -n --arg a "${addr_a}" --arg b "${addr_b}" --arg proto "${proto}" \
                --argjson pkts "${total_packets:-0}" --arg bytes "${total_bytes}" \
                '{addr_a: $a, addr_b: $b, proto: $proto, packets: $pkts, bytes: $bytes}')")
        fi
    done <<< "${raw}"
 
    if [[ "${#entries[@]}" -eq 0 ]]; then
        echo "[]"
    else
        printf '%s\n' "${entries[@]}" | jq -s '.'
    fi
}
 
echo -n "[*] Extracting TCP conversations...      "
tcp_conv_json="$(parse_conversations tcp)"
tcp_conv_count="$(jq 'length' <<< "${tcp_conv_json}" 2>/dev/null || echo 0)"
echo "(${tcp_conv_count})"
 
echo -n "[*] Extracting UDP conversations...      "
udp_conv_json="$(parse_conversations udp)"
udp_conv_count="$(jq 'length' <<< "${udp_conv_json}" 2>/dev/null || echo 0)"
echo "(${udp_conv_count})"
 
# Combined, sorted-by-bytes top 10 conversations across both protocols.
top_conversations_json="$(jq -s 'add // [] | sort_by(-(.bytes | gsub(","; "") | gsub("[^0-9.]"; "") | tonumber? // 0)) | .[0:10]' <(echo "${tcp_conv_json}") <(echo "${udp_conv_json}") 2>/dev/null || echo "[]")"
 
# ---------------------------------------------------------------------------
# DNS queries.
# ---------------------------------------------------------------------------
echo -n "[*] Extracting DNS queries...            "
dns_tsv="$(tshark -r "${PCAP_PATH}" -Y 'dns.flags.response==0' -T fields \
    -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null || true)"
 
DNS_ENTRIES=()
LONG_LABEL_ENTRIES=()
if [[ -n "${dns_tsv}" ]]; then
    while IFS=$'\t' read -r ts src qname qtype; do
        [[ -z "${ts}" ]] && continue
        DNS_ENTRIES+=("$(jq -n --arg ts "${ts}" --arg src "${src}" --arg name "${qname}" --arg qtype "${qtype}" \
            '{timestamp: $ts, src_ip: $src, query: $name, qtype: $qtype}')")
        leftmost_label="${qname%%.*}"
        if [[ "${#leftmost_label}" -gt 50 ]]; then
            LONG_LABEL_ENTRIES+=("${qname} (${#leftmost_label} chars)")
        fi
    done <<< "${dns_tsv}"
fi
dns_count="${#DNS_ENTRIES[@]}"
echo "(${dns_count})"
if [[ "${dns_count}" -eq 0 ]]; then
    dns_json="[]"
else
    dns_json="$(printf '%s\n' "${DNS_ENTRIES[@]}" | jq -s '.')"
fi
 
# ---------------------------------------------------------------------------
# HTTP requests.
# ---------------------------------------------------------------------------
echo -n "[*] Extracting HTTP requests...          "
http_tsv="$(tshark -r "${PCAP_PATH}" -Y http.request -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null || true)"
 
HTTP_ENTRIES=()
if [[ -n "${http_tsv}" ]]; then
    while IFS=$'\t' read -r ts src dst host method uri; do
        [[ -z "${ts}" ]] && continue
        HTTP_ENTRIES+=("$(jq -n --arg ts "${ts}" --arg src "${src}" --arg dst "${dst}" \
            --arg host "${host}" --arg method "${method}" --arg uri "${uri}" \
            '{timestamp: $ts, src_ip: $src, dst_ip: $dst, host: $host, method: $method, uri: $uri}')")
    done <<< "${http_tsv}"
fi
http_count="${#HTTP_ENTRIES[@]}"
echo "(${http_count})"
if [[ "${http_count}" -eq 0 ]]; then
    http_json="[]"
else
    http_json="$(printf '%s\n' "${HTTP_ENTRIES[@]}" | jq -s '.')"
fi
 
# ---------------------------------------------------------------------------
# TLS SNI.
# ---------------------------------------------------------------------------
echo -n "[*] Extracting TLS SNI...                "
tls_tsv="$(tshark -r "${PCAP_PATH}" -Y 'tls.handshake.type==1' -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null || true)"
 
TLS_ENTRIES=()
if [[ -n "${tls_tsv}" ]]; then
    while IFS=$'\t' read -r ts src dst sni; do
        [[ -z "${ts}" ]] && continue
        TLS_ENTRIES+=("$(jq -n --arg ts "${ts}" --arg src "${src}" --arg dst "${dst}" --arg sni "${sni}" \
            '{timestamp: $ts, src_ip: $src, dst_ip: $dst, sni: $sni}')")
    done <<< "${tls_tsv}"
fi
tls_count="${#TLS_ENTRIES[@]}"
echo "(${tls_count})"
if [[ "${tls_count}" -eq 0 ]]; then
    tls_json="[]"
else
    tls_json="$(printf '%s\n' "${TLS_ENTRIES[@]}" | jq -s '.')"
fi
 
# ---------------------------------------------------------------------------
# File transfer indicators.
# ---------------------------------------------------------------------------
echo -n "[*] Extracting file transfers...         "
files_tsv="$(tshark -r "${PCAP_PATH}" -Y 'http.content_type or smb2.filename' -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename 2>/dev/null || true)"
 
FILE_ENTRIES=()
if [[ -n "${files_tsv}" ]]; then
    while IFS=$'\t' read -r ts src dst http_data smb_name; do
        [[ -z "${ts}" ]] && continue
        FILE_ENTRIES+=("$(jq -n --arg ts "${ts}" --arg src "${src}" --arg dst "${dst}" \
            --arg http_data "${http_data}" --arg smb_name "${smb_name}" \
            '{timestamp: $ts, src_ip: $src, dst_ip: $dst, http_file_data_present: ($http_data != ""), smb_filename: $smb_name}')")
    done <<< "${files_tsv}"
fi
file_count="${#FILE_ENTRIES[@]}"
echo "(${file_count})"
if [[ "${file_count}" -eq 0 ]]; then
    files_json="[]"
else
    files_json="$(printf '%s\n' "${FILE_ENTRIES[@]}" | jq -s '.')"
fi
 
# ---------------------------------------------------------------------------
# Protocol distribution, from `tshark -q -z io,phs`'s hierarchical tree
# output - top-level protocols under `ip` (tcp/udp/icmp/other), expressed
# as a percentage of total frames.
# ---------------------------------------------------------------------------
echo -n "[*] Protocol distribution...             "
phs_raw="$(tshark -r "${PCAP_PATH}" -q -z io,phs 2>/dev/null || true)"
 
proto_tcp_frames="$(grep -oP '^\s*tcp\s+frames:\K[0-9]+' <<< "${phs_raw}" | head -1 || echo 0)"
proto_udp_frames="$(grep -oP '^\s*udp\s+frames:\K[0-9]+' <<< "${phs_raw}" | head -1 || echo 0)"
proto_icmp_frames="$(grep -oP '^\s*icmp\s+frames:\K[0-9]+' <<< "${phs_raw}" | head -1 || echo 0)"
[[ -z "${proto_tcp_frames}" ]] && proto_tcp_frames=0
[[ -z "${proto_udp_frames}" ]] && proto_udp_frames=0
[[ -z "${proto_icmp_frames}" ]] && proto_icmp_frames=0
 
total_frames="${packet_count}"
proto_dist_display="(no protocol data)"
proto_dist_json="[]"
if [[ "${total_frames}" -gt 0 ]]; then
    tcp_pct="$(awk -v a="${proto_tcp_frames}" -v t="${total_frames}" 'BEGIN{printf "%.0f", (a/t)*100}')"
    udp_pct="$(awk -v a="${proto_udp_frames}" -v t="${total_frames}" 'BEGIN{printf "%.0f", (a/t)*100}')"
    icmp_pct="$(awk -v a="${proto_icmp_frames}" -v t="${total_frames}" 'BEGIN{printf "%.0f", (a/t)*100}')"
    other_frames=$(( total_frames - proto_tcp_frames - proto_udp_frames - proto_icmp_frames ))
    [[ "${other_frames}" -lt 0 ]] && other_frames=0
    other_pct="$(awk -v a="${other_frames}" -v t="${total_frames}" 'BEGIN{printf "%.0f", (a/t)*100}')"
    proto_dist_display="tcp ${tcp_pct}%, udp ${udp_pct}%, icmp ${icmp_pct}%, other ${other_pct}%"
    proto_dist_json="$(jq -n --argjson tcp "${tcp_pct}" --argjson udp "${udp_pct}" --argjson icmp "${icmp_pct}" --argjson other "${other_pct}" \
        '{tcp_pct: $tcp, udp_pct: $udp, icmp_pct: $icmp, other_pct: $other}')"
fi
echo "(${proto_dist_display})"
 
# ---------------------------------------------------------------------------
# 3. Short stdout summary: top 5 conversations, long DNS labels.
# ---------------------------------------------------------------------------
echo "Top conversations:"
jq -r '.[0:5][] | "  \(.addr_a) <-> \(.addr_b)  \(.proto)  \(.packets) pkts  \(.bytes)"' <<< "${top_conversations_json}" 2>/dev/null
 
echo "Long DNS labels (> 50 chars):"
if [[ "${#LONG_LABEL_ENTRIES[@]}" -eq 0 ]]; then
    echo "  (none)"
else
    for entry in "${LONG_LABEL_ENTRIES[@]}"; do
        echo "  ${entry}"
    done
fi
 
# ---------------------------------------------------------------------------
# Emit pcap_findings.json
# ---------------------------------------------------------------------------
jq -n \
    --arg pcap "${PCAP_PATH}" \
    --arg duration "${duration}" \
    --argjson packet_count "${packet_count}" \
    --argjson tcp_conversations "${tcp_conv_json}" \
    --argjson udp_conversations "${udp_conv_json}" \
    --argjson top_conversations "${top_conversations_json}" \
    --argjson dns_queries "${dns_json}" \
    --argjson http_requests "${http_json}" \
    --argjson tls_sni "${tls_json}" \
    --argjson file_transfers "${files_json}" \
    --argjson protocol_distribution "${proto_dist_json}" \
    '{
        pcap: $pcap,
        duration_seconds: $duration,
        packet_count: $packet_count,
        tcp_conversations: $tcp_conversations,
        udp_conversations: $udp_conversations,
        top_conversations: $top_conversations,
        dns_queries: $dns_queries,
        http_requests: $http_requests,
        tls_sni: $tls_sni,
        file_transfers: $file_transfers,
        protocol_distribution: $protocol_distribution
    }' > "${OUTPUT_PATH}"
 
echo ""
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
exit 0
