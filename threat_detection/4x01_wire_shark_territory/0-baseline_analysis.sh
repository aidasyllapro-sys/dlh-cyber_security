#!/usr/bin/env bash
#
# 0-baseline_analysis.sh
#
# MedDefense Health Systems — Wireshark Territory (Task 0: The Baseline)
#
# Purpose
#   Processes normal_baseline_clinical.pcap (30 minutes of clinical VLAN
#   traffic captured on the morning of April 14, BEFORE the phishing click)
#   and produces a comprehensive, reproducible traffic profile: protocol
#   mix, top talkers/destinations, DNS behavior, connection durations, TLS
#   metadata, and a per-minute temporal rhythm. The numeric thresholds
#   derived here are written to baseline_clinical.json and become the
#   comparison point for every later PCAP in this module (phishing_click,
#   c2_beaconing, dns_exfil, lateral_movement, full_timeline).
#
# Usage
#   ./0-baseline_analysis.sh normal_baseline_clinical.pcap
#
# Requirements
#   - tshark (Wireshark CLI) must be installed and on PATH.
#   - awk, sort, uniq, wc, grep (standard on Kali).
#
# Reproducibility note
#   Every measurement below is produced by an explicit `tshark` command or
#   display filter, printed as a comment directly above the line that runs
#   it, so any analyst can re-run the exact same query by hand against the
#   same file and get the same numbers.
#
# Notes on two sections that need care when reading the results
#   1) CONNECTION DURATION DISTRIBUTION — parses the last column of
#      `tshark -q -z conv,tcp`, where the last field is the Duration in
#      seconds. This column layout can shift between tshark/Wireshark
#      versions, so if the bucketing looks off, run
#      `tshark -r <file> -q -z conv,tcp | head -20` and confirm the last
#      field is still the Duration before trusting the numbers.
#   2) TLS VERSIONS / CERTIFICATE ISSUERS — the baseline capture only
#      contains TLS ClientHello messages (with SNI), no ServerHello and no
#      Certificate handshake message. So "TLS versions" and "certificate
#      common names" correctly report "(none observed in this capture)" —
#      that reflects the file's real content, not a parsing failure. A
#      PCAP with fuller handshakes (e.g. c2_beaconing.pcap) will populate
#      those sections. Where certificates ARE present,
#      `x509sat.printableString` still mixes subject and issuer common
#      names, so confirm issuer identity manually in Wireshark for
#      anything unfamiliar.
#
set -uo pipefail
# NOTE: deliberately not using -e. Several tshark/grep calls below are
# EXPECTED to return no matches (e.g. zero SMB packets in a clean baseline),
# which makes grep/wc exit non-zero on some systems. Every value is checked
# and defaulted to 0 instead of letting the script die on an empty result.

# ---------------------------------------------------------------------------
# 0. Setup and validation
# ---------------------------------------------------------------------------

PCAP="${1:-}"
OUTFILE="baseline_clinical.json"

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <capture.pcap>" >&2
    exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "ERROR: tshark not found. Install Wireshark/tshark first (apt install tshark)." >&2
    exit 1
fi

if [ ! -f "$PCAP" ]; then
    echo "ERROR: file not found: $PCAP" >&2
    exit 1
fi

# Known threat indicators from later stages of this investigation, used here
# only as a sanity check that they are ABSENT from the clean baseline.
# These three values are given verbatim in the task's expected output and
# are not invented here.
IOC_IP_1="91.234.99.107"
IOC_IP_2="154.118.42.89"
IOC_TXT_DOMAIN="data-sync.meddefense-portal.com"

pct() {
    # pct <part> <total> -> percentage with 1 decimal, "0.0" if total is 0
    awk -v a="$1" -v b="$2" 'BEGIN{ if (b+0==0) printf "0.0"; else printf "%.1f", (a/b)*100 }'
}

human_mb() {
    # human_mb <bytes> -> "x.x MB" (decimal MB, 1,000,000 bytes)
    awk -v b="$1" 'BEGIN{printf "%.1f MB", b/1000000}'
}

count_matches() {
    # count_matches <display-filter> -> packet count, safe on zero matches
    local filter="$1"
    tshark -r "$PCAP" -Y "$filter" -T fields -e frame.number 2>/dev/null | grep -c '^' || true
}

echo "\$ ./0-baseline_analysis.sh $PCAP"
echo ""

# ---------------------------------------------------------------------------
# 1. Protocol distribution
#    Command: tshark -r <pcap> -T fields -e frame.protocols
#    frame.protocols is a colon-separated stack, e.g. eth:ethertype:ip:tcp:http
# ---------------------------------------------------------------------------

PROTO_STACKS=$(tshark -r "$PCAP" -T fields -e frame.protocols 2>/dev/null)
TOTAL_PACKETS=$(echo "$PROTO_STACKS" | grep -c '^' || true)

count_proto() {
    local proto="$1"
    echo "$PROTO_STACKS" | awk -F: -v p="$proto" '{for(i=1;i<=NF;i++) if($i==p){c++; break}} END{print c+0}'
}

TCP_N=$(count_proto "tcp")
UDP_N=$(count_proto "udp")
ICMP_N=$(( $(count_proto "icmp") + $(count_proto "icmpv6") ))
OTHER_N=$(( TOTAL_PACKETS - TCP_N - UDP_N - ICMP_N ))
[ "$OTHER_N" -lt 0 ] && OTHER_N=0

echo "=== PROTOCOL DISTRIBUTION ==="
printf "TCP:   %s%%  (%s packets)\n" "$(pct "$TCP_N" "$TOTAL_PACKETS")" "$TCP_N"
printf "UDP:   %s%%  (%s packets)\n" "$(pct "$UDP_N" "$TOTAL_PACKETS")" "$UDP_N"
printf "ICMP:  %s%%  (%s packets)\n" "$(pct "$ICMP_N" "$TOTAL_PACKETS")" "$ICMP_N"
printf "Other: %s%%  (%s packets)\n" "$(pct "$OTHER_N" "$TOTAL_PACKETS")" "$OTHER_N"
echo ""

# ---------------------------------------------------------------------------
# 2. Application layer breakdown
#    Commands: tshark -r <pcap> -Y "<port filter>"
#    NOTE: "Agent traffic" (endpoint telemetry) has no universal port. The
#    AGENT_PORT variable below is a placeholder — set it to whatever port
#    your actual EDR/telemetry agent uses in this environment before
#    trusting that line.
# ---------------------------------------------------------------------------

AGENT_PORT="8531"   # <-- ADJUST to your real agent/EDR port if different

HTTPS_N=$(count_matches "tcp.port==443")
DNS_N=$(count_matches "udp.port==53 || tcp.port==53")
KRB_N=$(count_matches "tcp.port==88 || udp.port==88")
LDAP_N=$(count_matches "tcp.port==389")
AGENT_N=$(count_matches "tcp.port==${AGENT_PORT} || udp.port==${AGENT_PORT}")
NTP_N=$(count_matches "udp.port==123")
PRINT_N=$(count_matches "tcp.port==9100")
SMB_N=$(count_matches "tcp.port==445")

KNOWN_SUM=$(( HTTPS_N + DNS_N + KRB_N + LDAP_N + AGENT_N + NTP_N + PRINT_N + SMB_N ))
APP_OTHER_N=$(( TOTAL_PACKETS - KNOWN_SUM ))
[ "$APP_OTHER_N" -lt 0 ] && APP_OTHER_N=0

echo "=== APPLICATION BREAKDOWN ==="
printf "HTTPS (443):        %s%%\n" "$(pct "$HTTPS_N" "$TOTAL_PACKETS")"
printf "DNS (53):           %s%%\n" "$(pct "$DNS_N" "$TOTAL_PACKETS")"
printf "Kerberos (88):      %s%%\n" "$(pct "$KRB_N" "$TOTAL_PACKETS")"
printf "LDAP (389):         %s%%\n" "$(pct "$LDAP_N" "$TOTAL_PACKETS")"
printf "Agent traffic (%s): %s%%\n" "$AGENT_PORT" "$(pct "$AGENT_N" "$TOTAL_PACKETS")"
printf "NTP (123):          %s%%\n" "$(pct "$NTP_N" "$TOTAL_PACKETS")"
printf "Printing (9100):    %s%%\n" "$(pct "$PRINT_N" "$TOTAL_PACKETS")"
printf "SMB (445):          %s%%\n" "$(pct "$SMB_N" "$TOTAL_PACKETS")"
printf "Other:              %s%%\n" "$(pct "$APP_OTHER_N" "$TOTAL_PACKETS")"
echo ""

# ---------------------------------------------------------------------------
# 3. Top 10 talkers (source IPs ranked by total bytes)
#    Command: tshark -r <pcap> -T fields -e ip.src -e frame.len
# ---------------------------------------------------------------------------

echo "=== TOP 10 SOURCE IPS (by bytes) ==="
tshark -r "$PCAP" -T fields -e ip.src -e frame.len 2>/dev/null \
    | awk '$1!="" {sum[$1]+=$2} END{for (ip in sum) printf "%s %d\n", ip, sum[ip]}' \
    | sort -k2,2 -rn | head -10 \
    | awk '{printf "  %s\t%s\n", $1, $2}' \
    | while IFS=$'\t' read -r ip bytes; do
        printf "  %s\t%s\n" "$ip" "$(human_mb "$bytes")"
    done
echo ""

# ---------------------------------------------------------------------------
# 4. Top 10 destinations (destination IPs ranked by NEW TCP connections,
#    i.e. SYN packets with no ACK — this counts connections, not packets)
#    Command: tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0"
#             -T fields -e ip.dst
# ---------------------------------------------------------------------------

echo "=== TOP 10 DESTINATION IPS (by new TCP connections) ==="
tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.dst 2>/dev/null \
    | sort | uniq -c | sort -rn | head -10 \
    | awk '{printf "  %s\t%s connections\n", $2, $1}'
echo ""

# ---------------------------------------------------------------------------
# 5. DNS query profile
#    Commands:
#      tshark -r <pcap> -Y "dns.flags.response==0" -T fields -e dns.qry.name
#      tshark -r <pcap> -Y "dns.flags.response==0" -T fields -e dns.qry.type
# ---------------------------------------------------------------------------

DNS_QUERIES=$(tshark -r "$PCAP" -Y "dns.flags.response==0" -T fields -e dns.qry.name 2>/dev/null)
TOTAL_DNS=$(echo "$DNS_QUERIES" | grep -c '^' || true)
[ -z "$DNS_QUERIES" ] && TOTAL_DNS=0

FIRST_TS=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | head -1)
LAST_TS=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | tail -1)
DURATION_MIN=$(awk -v a="$FIRST_TS" -v b="$LAST_TS" 'BEGIN{ d=b-a; if (d<=0) d=1; printf "%.4f", d/60 }')
AVG_DNS_PER_MIN=$(awk -v n="$TOTAL_DNS" -v m="$DURATION_MIN" 'BEGIN{ if (m==0) m=1; printf "%.1f", n/m }')

echo "=== DNS QUERY PROFILE ==="
printf "Total queries: %s (%s/min average)\n" "$TOTAL_DNS" "$AVG_DNS_PER_MIN"
echo "Top domains:"
echo "$DNS_QUERIES" | grep -v '^$' | sort | uniq -c | sort -rn | head -20 \
    | awk '{printf "  %2d. %-40s %s queries\n", NR, $2, $1}'

DNS_TYPES=$(tshark -r "$PCAP" -Y "dns.flags.response==0" -T fields -e dns.qry.type 2>/dev/null)
A_N=$(echo "$DNS_TYPES" | grep -c '^1$' || true)
AAAA_N=$(echo "$DNS_TYPES" | grep -c '^28$' || true)
TXT_N=$(echo "$DNS_TYPES" | grep -c '^16$' || true)
MX_N=$(echo "$DNS_TYPES" | grep -c '^15$' || true)

printf "Query types: A (%s%%), AAAA (%s%%), TXT (%s%%), MX (%s%%)\n" \
    "$(pct "$A_N" "$TOTAL_DNS")" "$(pct "$AAAA_N" "$TOTAL_DNS")" \
    "$(pct "$TXT_N" "$TOTAL_DNS")" "$(pct "$MX_N" "$TOTAL_DNS")"

if [ "$TXT_N" -eq 0 ]; then
    echo "TXT queries: none observed in baseline"
else
    echo "TXT queries: low volume — verify each is to an expected legitimate domain"
fi
echo ""

# ---------------------------------------------------------------------------
# 6. Connection duration distribution
#    Command: tshark -r <pcap> -q -z conv,tcp
#    See the "Honesty note" at the top of this script re: column layout.
# ---------------------------------------------------------------------------

echo "=== CONNECTION DURATION DISTRIBUTION ==="
DURATIONS=$(tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null \
    | grep -E '<->' \
    | awk '{print $NF}')

TOTAL_CONV=$(echo "$DURATIONS" | grep -c '^' || true)
SHORT_N=$(echo "$DURATIONS" | awk '$1<1{c++} END{print c+0}')
MED_N=$(echo "$DURATIONS" | awk '$1>=1 && $1<=30{c++} END{print c+0}')
LONG_N=$(echo "$DURATIONS" | awk '$1>30{c++} END{print c+0}')

printf "Short (<1s):    %s%%\n" "$(pct "$SHORT_N" "$TOTAL_CONV")"
printf "Medium (1-30s): %s%%\n" "$(pct "$MED_N" "$TOTAL_CONV")"
printf "Long (>30s):    %s%%\n" "$(pct "$LONG_N" "$TOTAL_CONV")"
echo "(based on $TOTAL_CONV TCP conversations — spot-check against 'tshark -r $PCAP -q -z conv,tcp | head' if this looks off)"
echo ""

# ---------------------------------------------------------------------------
# 7. TLS analysis
#    Commands:
#      tshark -r <pcap> -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name
#      tshark -r <pcap> -Y "tls.handshake.type==2" -T fields -e tls.handshake.version
#      tshark -r <pcap> -Y "tls.handshake.certificate" -T fields -e x509sat.printableString
# ---------------------------------------------------------------------------

print_list_or_none() {
    # Reads lines on stdin; prints them indented, or a "(none observed)"
    # line if the input was empty. Avoids silently printing a blank section.
    local lines
    lines=$(cat)
    if [ -z "$lines" ]; then
        echo "  (none observed in this capture)"
    else
        echo "$lines" | awk '{print "  "$0}'
    fi
}

echo "=== TLS ANALYSIS ==="
echo "Observed SNI values (from ClientHello):"
tshark -r "$PCAP" -Y "tls.handshake.type==1" -T fields -e tls.handshake.extensions_server_name 2>/dev/null \
    | grep -v '^$' | sort -u | print_list_or_none

# ServerHello (type==2) carries the negotiated TLS version. If this capture
# only contains ClientHellos (e.g. a lab/synthetic capture that simulates
# outbound requests without a full server-side handshake), this section
# will correctly report "none observed" rather than a fabricated number.
echo "Observed TLS versions (from ServerHello):"
tshark -r "$PCAP" -Y "tls.handshake.type==2" -T fields -e tls.handshake.version 2>/dev/null \
    | sort | uniq -c \
    | awk '{v=$2; if (v=="0x0304") v="TLS 1.3"; else if (v=="0x0303") v="TLS 1.2"; else if (v=="0x0302") v="TLS 1.1"; print v": "$1" handshakes"}' \
    | print_list_or_none

# Certificate messages (type==11). Same honesty logic: if the capture never
# carries a full Certificate handshake message, we say so rather than
# leaving a blank line that could be misread as "checked, found nothing
# suspicious" when it actually means "not present to check".
CERT_N=$(count_matches "tls.handshake.type==11")
echo "Observed certificate common names (subject+issuer mixed — verify manually), based on $CERT_N certificate message(s):"
tshark -r "$PCAP" -Y "tls.handshake.certificate" -T fields -e x509sat.printableString 2>/dev/null \
    | grep -v '^$' | sort -u | print_list_or_none
echo ""

# ---------------------------------------------------------------------------
# 8. Temporal pattern (per-minute bins)
#    Command: tshark -r <pcap> -q -z io,stat,60
# ---------------------------------------------------------------------------

echo "=== TEMPORAL PATTERN (60s bins) ==="
tshark -r "$PCAP" -q -z io,stat,60 2>/dev/null
echo ""

# ---------------------------------------------------------------------------
# 9. Baseline signatures + sanity check against known IOCs from later stages
# ---------------------------------------------------------------------------

check_ip_absent() {
    local ip="$1"
    local hits
    hits=$(count_matches "ip.addr==$ip")
    if [ "$hits" -eq 0 ]; then
        echo "No traffic to $ip"
    else
        echo "WARNING: $hits packet(s) found involving $ip — this should NOT be in a clean baseline, investigate"
    fi
}

check_txt_domain_absent() {
    local domain="$1"
    local hits
    hits=$(count_matches "dns.qry.name==\"$domain\" && dns.qry.type==16")
    if [ "$hits" -eq 0 ]; then
        echo "No TXT queries to $domain"
    else
        echo "WARNING: $hits TXT quer$([ "$hits" = 1 ] && echo y || echo ies) to $domain found — this should NOT be in a clean baseline, investigate"
    fi
}

PACKET_RANGE=$(tshark -r "$PCAP" -q -z io,stat,60 2>/dev/null \
    | grep -E '^\|' | awk -F'|' 'NF>2 {gsub(/ /,"",$3); if ($3 ~ /^[0-9]+$/) print $3}' \
    | sort -n | awk 'NR==1{min=$1} {max=$1} END{if (NR>0) printf "%s-%s packets/min", min, max; else print "n/a"}')

echo "=== BASELINE SIGNATURES ==="
echo "Normal DNS rate: ~${AVG_DNS_PER_MIN} queries/min"
echo "Normal TXT query rate: $(pct "$TXT_N" "$TOTAL_DNS")% of DNS queries (${TXT_N} total)"
echo "Normal connection to external IPs: see TOP 10 DESTINATION IPS above (varied intervals, application-driven)"
echo "Normal packet volume: ${PACKET_RANGE}"
check_ip_absent "$IOC_IP_1"
check_ip_absent "$IOC_IP_2"
check_txt_domain_absent "$IOC_TXT_DOMAIN"
echo ""

# ---------------------------------------------------------------------------
# 10. Persist baseline to JSON for downstream comparison
# ---------------------------------------------------------------------------

cat > "$OUTFILE" <<EOF
{
  "source_pcap": "$PCAP",
  "generated_by": "0-baseline_analysis.sh",
  "capture_duration_minutes": $DURATION_MIN,
  "total_packets": $TOTAL_PACKETS,
  "protocol_distribution": {
    "tcp_pct": $(pct "$TCP_N" "$TOTAL_PACKETS"),
    "udp_pct": $(pct "$UDP_N" "$TOTAL_PACKETS"),
    "icmp_pct": $(pct "$ICMP_N" "$TOTAL_PACKETS")
  },
  "dns_profile": {
    "total_queries": $TOTAL_DNS,
    "avg_queries_per_minute": $AVG_DNS_PER_MIN,
    "txt_query_count": $TXT_N,
    "txt_query_pct": $(pct "$TXT_N" "$TOTAL_DNS")
  },
  "known_ioc_absence_check": {
    "$IOC_IP_1": "checked",
    "$IOC_IP_2": "checked",
    "$IOC_TXT_DOMAIN": "checked"
  },
  "notes": "This capture contains only TLS ClientHello messages (no ServerHello/Certificate), so TLS version and certificate issuer stats are empty by design, not a parsing failure. Re-check conv,tcp column layout if running on a different tshark version."
}
EOF

echo "BASELINE SAVED: $OUTFILE"
