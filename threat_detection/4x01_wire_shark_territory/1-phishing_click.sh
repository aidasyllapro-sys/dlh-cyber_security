#!/bin/bash
#
# 1-phishing_click.sh
#
# MedDefense Health Systems — Wireshark Territory (Task 1: The Click in the Wire)
#
# Purpose
#   Analyzes phishing_click.pcap, the capture covering the moment Diane
#   Marsh (WS-NURSE-04) clicked the link in E2 (4x00 phishing investigation).
#   Extracts, straight from the packets: the DNS resolution of
#   meddefense-portal[.]com, the TLS ClientHello/ServerHello/certificate
#   exchange, the data volumes in each direction, every relevant timestamp,
#   whether a query to the real meddefense.com portal follows the session,
#   and how this evidence correlates with the 4x00 IOCs
#   (meddefense-portal[.]com, 91.234.99.107).
#
#   This script uses tshark only. Wireshark's GUI is for manual, exploratory
#   investigation and is not part of this automated deliverable.
#
# Usage
#   ./1-phishing_click.sh phishing_click.pcap
#
# Requirements
#   - tshark (Wireshark CLI) must be installed and on PATH.
#   - awk, sort, grep, sed (standard on Kali).
#   - python3 (used only as a fallback to decode a plaintext CERT: marker
#     when a capture does not carry a real, ASN.1-decodable certificate).
#     If python3 is missing, that one fallback is skipped and the script
#     says so instead of guessing certificate details.
#   - shellcheck (to verify this script before pushing; not required at runtime).
#
# Reproducibility note
#   Every measurement below is produced by an explicit tshark command or
#   display filter, printed as a comment directly above the line that runs
#   it, so any analyst can re-run the exact same query by hand against the
#   same file and get the same numbers and timestamps.
#
set -uo pipefail
# Deliberately not using -e: several tshark/grep calls below are expected to
# return no matches (e.g. no post-click query to the real portal), which
# makes grep/wc exit non-zero on some systems. Every value is checked and
# defaulted instead of letting the script die on an empty result.

# ---------------------------------------------------------------------------
# 0. Setup and validation
# ---------------------------------------------------------------------------

PCAP="${1:-}"
OUTFILE="phishing_click_findings.json"

# Known IOCs from the 4x00 phishing investigation, used here only to
# confirm (or not) that this capture actually involves them. They are not
# assumed present — the script checks for them in the packets.
IOC_DOMAIN="meddefense-portal.com"
IOC_IP="91.234.99.107"
REAL_PORTAL_DOMAIN="meddefense.com"

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <phishing_click.pcap>" >&2
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

count_matches() {
    # count_matches <display-filter> -> packet count, safe on zero matches
    local filter="$1"
    tshark -r "$PCAP" -Y "$filter" -T fields -e frame.number 2>/dev/null | grep -c '^' || true
}

fmt_time() {
    # fmt_time <epoch> -> HH:MM:SS.mmm (local capture time as tshark prints it)
    awk -v t="$1" 'BEGIN{
        if (t=="" ) { print "n/a"; exit }
        h=int(t/3600)%24; m=int(t/60)%60; s=t-int(t/60)*60;
        printf "%02d:%02d:%06.3f", h, m, s
    }'
}

echo "\$ ./1-phishing_click.sh $PCAP"
echo ""

# ---------------------------------------------------------------------------
# 1. DNS resolution of the phishing domain
#    Commands:
#      tshark -r <pcap> -Y "dns.qry.name==\"meddefense-portal.com\" && dns.flags.response==0" \
#             -T fields -e frame.time_epoch -e ip.src -e ip.dst
#      tshark -r <pcap> -Y "dns.qry.name==\"meddefense-portal.com\" && dns.flags.response==1" \
#             -T fields -e frame.time_epoch -e dns.a -e dns.resp.ttl -e ip.src -e ip.dst
# ---------------------------------------------------------------------------

echo "=== DNS RESOLUTION ==="

DNS_Q=$(tshark -r "$PCAP" -Y "dns.qry.name==\"$IOC_DOMAIN\" && dns.flags.response==0" \
    -T fields -e frame.time_epoch -e ip.src -e ip.dst 2>/dev/null | head -1)
DNS_Q_TS=$(echo "$DNS_Q" | awk -F'\t' '{print $1}')
DNS_Q_SRC=$(echo "$DNS_Q" | awk -F'\t' '{print $2}')
DNS_Q_DST=$(echo "$DNS_Q" | awk -F'\t' '{print $3}')

DNS_R=$(tshark -r "$PCAP" -Y "dns.qry.name==\"$IOC_DOMAIN\" && dns.flags.response==1" \
    -T fields -e frame.time_epoch -e dns.a -e dns.resp.ttl 2>/dev/null | head -1)
DNS_R_TS=$(echo "$DNS_R" | awk -F'\t' '{print $1}')
DNS_R_IP=$(echo "$DNS_R" | awk -F'\t' '{print $2}')
DNS_R_TTL=$(echo "$DNS_R" | awk -F'\t' '{print $3}')

if [ -z "$DNS_Q_TS" ]; then
    echo "No DNS query for $IOC_DOMAIN found in this capture."
else
    printf "%s  Query: %s\n" "$(fmt_time "$DNS_Q_TS")" "$IOC_DOMAIN"
    printf "%s  Response: %s\n" "$(fmt_time "$DNS_R_TS")" "${DNS_R_IP:-n/a}"
    printf "TTL: %s\n" "${DNS_R_TTL:-n/a}"
    printf "Source: %s -> %s\n" "${DNS_Q_SRC:-n/a}" "${DNS_Q_DST:-n/a}"
fi
echo ""

# ---------------------------------------------------------------------------
# 2. TCP handshake + TLS ClientHello
#    Commands:
#      tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==<IOC_IP>" \
#             -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport
#      tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==1 && ip.src==<IOC_IP>" \
#             -T fields -e frame.time_epoch
#      tshark -r <pcap> -Y "tls.handshake.type==1 && ip.dst==<IOC_IP>" \
#             -T fields -e frame.time_epoch -e tls.handshake.extensions_server_name \
#             -e tls.handshake.version -e tls.handshake.ciphersuite
# ---------------------------------------------------------------------------

echo "=== TLS HANDSHAKE ==="

SYN_TS=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==$DNS_R_IP" \
    -T fields -e frame.time_epoch 2>/dev/null | head -1)
SYNACK_TS=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==1 && ip.src==$DNS_R_IP" \
    -T fields -e frame.time_epoch 2>/dev/null | head -1)

CH_LINE=$(tshark -r "$PCAP" -Y "tls.handshake.type==1 && ip.dst==$DNS_R_IP" \
    -T fields -e frame.time_epoch -e tls.handshake.extensions_server_name -e tls.handshake.version 2>/dev/null | head -1)
CH_TS=$(echo "$CH_LINE" | awk -F'\t' '{print $1}')
CH_SNI=$(echo "$CH_LINE" | awk -F'\t' '{print $2}')
CH_VER_RAW=$(echo "$CH_LINE" | awk -F'\t' '{print $3}')

# tls.handshake.version in the ClientHello is the legacy field (usually
# 0x0303 for compatibility); the actual offered max version is advertised
# in the supported_versions extension. Both are pulled for transparency.
CH_SUPPORTED_VERSIONS=$(tshark -r "$PCAP" -Y "tls.handshake.type==1 && ip.dst==$DNS_R_IP" \
    -T fields -e tls.handshake.extensions.supported_version 2>/dev/null | head -1)

CIPHERS=$(tshark -r "$PCAP" -Y "tls.handshake.type==1 && ip.dst==$DNS_R_IP" \
    -T fields -e tls.handshake.ciphersuite 2>/dev/null | head -1 | tr ',' '\n' | head -5 | paste -sd, -)

[ -n "$SYN_TS" ] && printf "%s  SYN -> %s:443\n" "$(fmt_time "$SYN_TS")" "$DNS_R_IP"
[ -n "$SYNACK_TS" ] && printf "%s  SYN-ACK\n" "$(fmt_time "$SYNACK_TS")"
if [ -n "$CH_TS" ]; then
    printf "%s  ClientHello\n" "$(fmt_time "$CH_TS")"
    printf "  SNI: %s\n" "${CH_SNI:-n/a}"
    printf "  TLS version offered (supported_versions ext): %s\n" "${CH_SUPPORTED_VERSIONS:-n/a (see legacy field: $CH_VER_RAW)}"
    printf "  Cipher suites (first 5 offered): %s\n" "${CIPHERS:-n/a}"
else
    echo "No TLS ClientHello to $DNS_R_IP found in this capture."
fi
echo ""

# ---------------------------------------------------------------------------
# 3. ServerHello + certificate details
#    Commands:
#      tshark -r <pcap> -Y "tls.record.content_type==22 && ip.src==<IOC_IP>" -T fields -e frame.time_epoch
#      tshark -r <pcap> -Y "tls.handshake.type==11 && ip.src==<IOC_IP>" -T fields \
#             -e x509sat.printableString -e x509sat.uTF8String \
#             -e x509af.notBefore -e x509af.notAfter -e x509af.serialNumber
#
#    Fallback for training/lab captures that don't carry a real,
#    ASN.1-decodable X.509 certificate: some synthetic PCAPs (this one
#    included) embed the certificate fields as a readable
#    "CERT:CN=...,ISSUER=...,NOTBEFORE=...,NOTAFTER=...,SERIAL=..." marker
#    inside the TLS record payload instead of a real DER certificate, so
#    tshark's x509 dissector has nothing to decode (tls.handshake.type==11
#    matches zero packets). When that happens, this falls back to reading
#    the record's raw TCP payload and extracting that marker directly:
#      tshark -r <pcap> -Y "frame contains \"CERT:\" && ip.src==<IOC_IP>" \
#             -T fields -e frame.time_epoch -e tcp.payload
#    then decodes the hex payload and pulls out the CERT:... substring.
# ---------------------------------------------------------------------------

# The TLS record layer still correctly tags this as a Handshake record
# (content type 22) even when the handshake sub-message itself is
# synthetic/undecodable, so this is used to time the ServerHello.
SH_TS=$(tshark -r "$PCAP" -Y "tls.record.content_type==22 && ip.src==$DNS_R_IP" \
    -T fields -e frame.time_epoch 2>/dev/null | head -1)

CERT_N=$(count_matches "tls.handshake.type==11 && ip.src==$DNS_R_IP")
CERT_SUBJECT=""
CERT_ISSUER=""
CERT_NOTBEFORE=""
CERT_NOTAFTER=""
CERT_SERIAL=""
CERT_SOURCE=""

if [ "$CERT_N" -gt 0 ]; then
    CERT_SOURCE="x509"
    # NOTE: x509sat.printableString/uTF8String return subject AND issuer
    # common names mixed together (Wireshark does not cleanly separate
    # them per-message in this field); reported as-is for manual review.
    CERT_SUBJECT=$(tshark -r "$PCAP" -Y "tls.handshake.type==11 && ip.src==$DNS_R_IP" \
        -T fields -e x509sat.printableString -e x509sat.uTF8String 2>/dev/null | head -1)
    CERT_NOTBEFORE=$(tshark -r "$PCAP" -Y "tls.handshake.type==11 && ip.src==$DNS_R_IP" \
        -T fields -e x509af.notBefore 2>/dev/null | head -1)
    CERT_NOTAFTER=$(tshark -r "$PCAP" -Y "tls.handshake.type==11 && ip.src==$DNS_R_IP" \
        -T fields -e x509af.notAfter 2>/dev/null | head -1)
    CERT_SERIAL=$(tshark -r "$PCAP" -Y "tls.handshake.type==11 && ip.src==$DNS_R_IP" \
        -T fields -e x509af.serialNumber 2>/dev/null | head -1)
elif command -v python3 >/dev/null 2>&1; then
    CERT_HEX=$(tshark -r "$PCAP" -Y "frame contains \"CERT:\" && ip.src==$DNS_R_IP" \
        -T fields -e tcp.payload 2>/dev/null | tr -d ':' | head -1)
    if [ -n "$CERT_HEX" ]; then
        CERT_LINE=$(python3 -c '
import sys, re
h = sys.stdin.read().strip()
try:
    b = bytes.fromhex(h)
except ValueError:
    sys.exit(0)
s = b.decode("latin1")
m = re.search(r"CERT:CN=([^,]+),ISSUER=([^,]+),NOTBEFORE=(\d{8}),NOTAFTER=(\d{8}),SERIAL=([0-9a-fA-F]+)", s)
if m:
    print("\t".join(m.groups()))
' <<< "$CERT_HEX")
        if [ -n "$CERT_LINE" ]; then
            CERT_SOURCE="plaintext_marker"
            CERT_SUBJECT=$(echo "$CERT_LINE" | awk -F'\t' '{print "CN="$1}')
            CERT_ISSUER=$(echo "$CERT_LINE" | awk -F'\t' '{print $2}')
            CERT_NOTBEFORE_RAW=$(echo "$CERT_LINE" | awk -F'\t' '{print $3}')
            CERT_NOTAFTER_RAW=$(echo "$CERT_LINE" | awk -F'\t' '{print $4}')
            CERT_SERIAL_RAW=$(echo "$CERT_LINE" | awk -F'\t' '{print $5}')
            CERT_NOTBEFORE=$(echo "$CERT_NOTBEFORE_RAW" | sed -E 's/([0-9]{4})([0-9]{2})([0-9]{2})/\1-\2-\3/')
            CERT_NOTAFTER=$(echo "$CERT_NOTAFTER_RAW" | sed -E 's/([0-9]{4})([0-9]{2})([0-9]{2})/\1-\2-\3/')
            CERT_SERIAL=$(echo "$CERT_SERIAL_RAW" | sed -E 's/(..)/\1:/g; s/:$//')
        fi
    fi
fi

if [ -n "$SH_TS" ]; then
    printf "%s  ServerHello%s\n" "$(fmt_time "$SH_TS")" "$([ -n "$CERT_SOURCE" ] && echo " + Certificate" || echo "")"
fi

if [ "$CERT_SOURCE" = "x509" ]; then
    echo "  Certificate common names observed (subject/issuer, verify manually which is which):"
    echo "$CERT_SUBJECT" | tr '\t' '\n' | grep -v '^$' | sort -u | awk '{print "    "$0}'
    printf "  Valid from: %s\n" "${CERT_NOTBEFORE:-n/a}"
    printf "  Valid until: %s\n" "${CERT_NOTAFTER:-n/a}"
    printf "  Serial: %s\n" "${CERT_SERIAL:-n/a}"
elif [ "$CERT_SOURCE" = "plaintext_marker" ]; then
    echo "  [captured via plaintext CERT: marker in the TLS record payload — this lab"
    echo "   capture does not carry a real ASN.1-encoded certificate for tshark's x509"
    echo "   dissector to decode, so the marker is read directly instead]"
    printf "  Subject: %s\n" "$CERT_SUBJECT"
    printf "  Issuer: %s\n" "$CERT_ISSUER"
    printf "  Valid from: %s\n" "$CERT_NOTBEFORE"
    printf "  Valid until: %s\n" "$CERT_NOTAFTER"
    printf "  Serial: %s\n" "$CERT_SERIAL"
else
    echo "No certificate data (neither a decodable X.509 message nor a plaintext CERT: marker) found from $DNS_R_IP in this capture — cannot report subject/issuer/validity/serial."
fi
echo ""

# ---------------------------------------------------------------------------
# 4 & 5. Data exchange volumes and connection timestamps
#    Commands:
#      tshark -r <pcap> -Y "ip.dst==<IOC_IP> && tcp.port==443" -T fields -e frame.len -e frame.time_epoch
#      tshark -r <pcap> -Y "ip.src==<IOC_IP> && tcp.port==443" -T fields -e frame.len -e frame.time_epoch
#      tshark -r <pcap> -Y "tcp.flags.fin==1 && ip.addr==<IOC_IP>" -T fields -e frame.time_epoch
# ---------------------------------------------------------------------------

echo "=== DATA EXCHANGE ==="

# All packets in the session, ordered by time, to establish connection
# start/close and the data-transfer window.
CONN_START_TS="$SYN_TS"
CONN_CLOSE_TS=$(tshark -r "$PCAP" -Y "(tcp.flags.fin==1 || tcp.flags.reset==1) && ip.addr==$DNS_R_IP" \
    -T fields -e frame.time_epoch 2>/dev/null | tail -1)

# Client -> server (application data only, i.e. after the handshake: TLS
# record type 23 / application data)
CLIENT_APPDATA=$(tshark -r "$PCAP" -Y "ip.dst==$DNS_R_IP && tcp.port==443 && tls.record.content_type==23" \
    -T fields -e frame.len -e frame.time_epoch 2>/dev/null)
CLIENT_BYTES=$(echo "$CLIENT_APPDATA" | awk -F'\t' '{sum+=$1} END{print sum+0}')
CLIENT_SEGMENTS=$(echo "$CLIENT_APPDATA" | grep -c '^' || true)
[ -z "$CLIENT_APPDATA" ] && CLIENT_SEGMENTS=0

SERVER_APPDATA=$(tshark -r "$PCAP" -Y "ip.src==$DNS_R_IP && tcp.port==443 && tls.record.content_type==23" \
    -T fields -e frame.len -e frame.time_epoch 2>/dev/null)
SERVER_BYTES=$(echo "$SERVER_APPDATA" | awk -F'\t' '{sum+=$1} END{print sum+0}')
SERVER_SEGMENTS=$(echo "$SERVER_APPDATA" | grep -c '^' || true)
[ -z "$SERVER_APPDATA" ] && SERVER_SEGMENTS=0

DATA_START_TS=$(printf "%s\n%s\n" "$(echo "$CLIENT_APPDATA" | awk -F'\t' '{print $2}' | head -1)" \
    "$(echo "$SERVER_APPDATA" | awk -F'\t' '{print $2}' | head -1)" | grep -v '^$' | sort -n | head -1)
DATA_END_TS=$(printf "%s\n%s\n" "$(echo "$CLIENT_APPDATA" | awk -F'\t' '{print $2}' | tail -1)" \
    "$(echo "$SERVER_APPDATA" | awk -F'\t' '{print $2}' | tail -1)" | grep -v '^$' | sort -n | tail -1)

DURATION=$(awk -v a="$CONN_START_TS" -v b="$CONN_CLOSE_TS" 'BEGIN{ if (a=="" || b=="") {print "n/a"} else printf "%.1f", b-a }')

printf "Connection start:      %s\n" "$(fmt_time "$CONN_START_TS")"
printf "Data transfer start:   %s\n" "$(fmt_time "$DATA_START_TS")"
printf "Data transfer end:     %s\n" "$(fmt_time "$DATA_END_TS")"
printf "Connection close:      %s\n" "$(fmt_time "$CONN_CLOSE_TS")"
printf "Duration: %s seconds (%s to %s)\n" "$DURATION" "$(fmt_time "$CONN_START_TS")" "$(fmt_time "$CONN_CLOSE_TS")"
printf "Client -> Server: %s bytes across %s TCP segments (application data only)\n" "$CLIENT_BYTES" "$CLIENT_SEGMENTS"
printf "Server -> Client: %s bytes across %s TCP segments (application data only)\n" "$SERVER_BYTES" "$SERVER_SEGMENTS"

LARGEST_CLIENT=$(echo "$CLIENT_APPDATA" | sort -t$'\t' -k1,1 -rn | head -1)
LARGEST_CLIENT_LEN=$(echo "$LARGEST_CLIENT" | awk -F'\t' '{print $1}')
LARGEST_CLIENT_TS=$(echo "$LARGEST_CLIENT" | awk -F'\t' '{print $2}')
if [ -n "$LARGEST_CLIENT_LEN" ]; then
    printf "Largest client TLS record: %s bytes at %s\n" "$LARGEST_CLIENT_LEN" "$(fmt_time "$LARGEST_CLIENT_TS")"
fi
echo ""

echo "[*] Analysis:"
echo "    The session is encrypted (TLS application data), so exact form"
echo "    field contents are NOT visible in this capture and this script"
echo "    makes no claim about what was actually typed or submitted."
echo "    This is a metadata-based assessment only, based on record sizes"
echo "    and direction, not decrypted content."
if [ -n "$LARGEST_CLIENT_LEN" ] && [ "$LARGEST_CLIENT_LEN" -gt 0 ] && [ "$LARGEST_CLIENT_LEN" -lt 2000 ]; then
    echo "    A largest client record of ${LARGEST_CLIENT_LEN} bytes is small and"
    echo "    consistent with a short HTTPS form submission (e.g. credentials"
    echo "    plus token/session data), but is equally consistent with other"
    echo "    small POST requests. This is a plausible interpretation, not a"
    echo "    confirmed fact — do not report it as proof of credential theft"
    echo "    without corroborating evidence (e.g. a confirmed compromise"
    echo "    matrix finding from the 4x00 investigation)."
else
    echo "    No small, form-sized client record was identified; insufficient"
    echo "    metadata here to support a credential-submission interpretation."
fi
echo ""

# ---------------------------------------------------------------------------
# 6/7. Post-click DNS behavior: query to the real portal
#    Command: tshark -r <pcap> -Y "dns.qry.name==\"meddefense.com\" && dns.flags.response==0" \
#             -T fields -e frame.time_epoch
# ---------------------------------------------------------------------------

echo "=== POST-CLICK BEHAVIOR ==="

REAL_Q=$(tshark -r "$PCAP" -Y "dns.qry.name==\"$REAL_PORTAL_DOMAIN\" && dns.flags.response==0" \
    -T fields -e frame.time_epoch 2>/dev/null | head -1)
REAL_R_LINE=$(tshark -r "$PCAP" -Y "dns.qry.name==\"$REAL_PORTAL_DOMAIN\" && dns.flags.response==1" \
    -T fields -e frame.time_epoch -e dns.a 2>/dev/null | head -1)
REAL_R_TS=$(echo "$REAL_R_LINE" | awk -F'\t' '{print $1}')
REAL_R_IP=$(echo "$REAL_R_LINE" | awk -F'\t' '{print $2}')

if [ -z "$REAL_Q" ]; then
    echo "No DNS query to the real $REAL_PORTAL_DOMAIN portal found after the phishing session in this capture."
else
    printf "%s  DNS query: %s\n" "$(fmt_time "$REAL_Q")" "$REAL_PORTAL_DOMAIN"
    [ -n "$REAL_R_TS" ] && printf "%s  DNS response: %s\n" "$(fmt_time "$REAL_R_TS")" "${REAL_R_IP:-n/a}"

    if [ -n "$REAL_R_IP" ]; then
        HTTPS_TS=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==$REAL_R_IP && tcp.port==443" \
            -T fields -e frame.time_epoch 2>/dev/null | head -1)
        [ -n "$HTTPS_TS" ] && printf "%s  HTTPS connection to %s:443\n" "$(fmt_time "$HTTPS_TS")" "$REAL_R_IP"
    fi

    echo ""
    echo "[*] Possible interpretation:"
    echo "    The workstation queried the real portal shortly after the"
    echo "    phishing session. This may indicate the user noticed something"
    echo "    wrong and navigated there deliberately, or that the phishing"
    echo "    site redirected her to the legitimate portal after harvesting"
    echo "    data. The packets alone cannot distinguish between these two;"
    echo "    treat this as a lead for further correlation, not a conclusion."
fi
echo ""

# ---------------------------------------------------------------------------
# 8. Correlation with the 4x00 phishing investigation
# ---------------------------------------------------------------------------

echo "=== 4x00 CORRELATION ==="

if [ -n "$DNS_Q_TS" ]; then
    echo "IOC domain match: $IOC_DOMAIN (queried at $(fmt_time "$DNS_Q_TS"))"
else
    echo "IOC domain match: NOT FOUND in this capture"
fi

if [ -n "$DNS_R_IP" ] && [ "$DNS_R_IP" = "$IOC_IP" ]; then
    echo "IOC IP match: $IOC_IP (resolved response)"
elif [ -n "$DNS_R_IP" ]; then
    echo "IOC IP MISMATCH: capture resolved $IOC_DOMAIN to $DNS_R_IP, not the expected $IOC_IP from 4x00 — investigate before concluding"
else
    echo "IOC IP match: NOT FOUND in this capture"
fi

if [ -n "$DNS_Q_TS" ] && [ "$DNS_R_IP" = "$IOC_IP" ]; then
    echo "Conclusion: this PCAP confirms the workstation contacted the phishing infrastructure identified in 4x00 (domain and IP both match), and adds network-level evidence (DNS, TLS, certificate, timestamps) that the 4x00 email-only investigation could not provide."
else
    echo "Conclusion: this PCAP does NOT fully confirm the expected 4x00 IOCs — review the discrepancy above before updating the investigation."
fi
echo ""

# ---------------------------------------------------------------------------
# 9. Persist findings to JSON
# ---------------------------------------------------------------------------

cat > "$OUTFILE" <<EOF
{
  "source_pcap": "$PCAP",
  "generated_by": "1-phishing_click.sh",
  "dns_resolution": {
    "query_time": "$(fmt_time "$DNS_Q_TS")",
    "response_time": "$(fmt_time "$DNS_R_TS")",
    "resolved_ip": "${DNS_R_IP:-null}",
    "ttl": "${DNS_R_TTL:-null}"
  },
  "tls": {
    "client_hello_time": "$(fmt_time "$CH_TS")",
    "sni": "${CH_SNI:-null}",
    "certificate_present": $([ -n "$CERT_SOURCE" ] && echo true || echo false),
    "certificate_source": "${CERT_SOURCE:-none}",
    "certificate_subject": "${CERT_SUBJECT:-null}",
    "certificate_issuer": "${CERT_ISSUER:-null}",
    "certificate_not_before": "${CERT_NOTBEFORE:-null}",
    "certificate_not_after": "${CERT_NOTAFTER:-null}",
    "certificate_serial": "${CERT_SERIAL:-null}"
  },
  "data_exchange": {
    "duration_seconds": "$DURATION",
    "client_to_server_bytes": $CLIENT_BYTES,
    "client_to_server_segments": $CLIENT_SEGMENTS,
    "server_to_client_bytes": $SERVER_BYTES,
    "server_to_client_segments": $SERVER_SEGMENTS
  },
  "post_click_real_portal_query": $([ -n "$REAL_Q" ] && echo true || echo false),
  "ioc_correlation": {
    "domain_match": $([ -n "$DNS_Q_TS" ] && echo true || echo false),
    "ip_match": $([ "$DNS_R_IP" = "$IOC_IP" ] && echo true || echo false)
  },
  "notes": "Data volumes are TLS application-data record bytes/segments, not raw frame totals, so header overhead is excluded. Credential-submission interpretation is metadata-based only; packet contents were not and cannot be read due to encryption."
}
EOF

echo "FINDINGS SAVED: $OUTFILE"
