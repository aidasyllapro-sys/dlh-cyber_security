#!/bin/bash
#
# 5-vpn_pivot.sh
#
# MedDefense Health Systems — Wireshark Territory (Task 5: The VPN Pivot)
#
# Purpose
#   Analyzes full_timeline.pcap for the VPN connection that bridges the
#   gap between the phishing click (April 14, 4x00) and the lateral
#   movement (April 15, Task 4): identifies the VPN session, geolocates the
#   external source IP, correlates the VPN timestamp against the first RDP
#   movement from Task 4, computes session duration, looks for an assigned
#   internal IP, and states plainly what the packet evidence proves versus
#   what it cannot prove on its own.
#
#   This script uses tshark for packet analysis and the system `whois`
#   command for geolocation/ASN lookups. Wireshark's GUI is for manual,
#   exploratory investigation and is not part of this automated deliverable.
#
# Usage
#   ./5-vpn_pivot.sh full_timeline.pcap
#
# Requirements
#   - tshark (Wireshark CLI) must be installed and on PATH.
#   - whois (apt install whois) for geolocation/ASN lookup — requires
#     outbound network access on this machine; if the lookup times out or
#     the command is missing, the script says so instead of inventing a
#     country or ASN.
#   - awk, sort, grep (standard on Kali).
#   - python3 (used for a couple of small correlations — timestamp math and
#     loading Task 4's JSON output if present. If missing, those specific
#     steps are skipped with a stated reason).
#
# Reproducibility note
#   Every measurement below is produced by an explicit tshark or whois
#   command, printed as a comment directly above the line that runs it, so
#   any analyst can re-run the exact same query by hand against the same
#   file and get the same numbers and timestamps.
#
# How the VPN connection is identified
#   Rather than searching for one specific hardcoded IP, this script looks
#   for the general pattern a remote-access VPN pivot produces: a TCP
#   session opened by a PUBLIC (non-RFC1918) source IP to a PRIVATE
#   (RFC1918) destination IP on a port commonly used for SSL-VPN /
#   clientless VPN gateways (443 by default here, since the task brief
#   describes an "SSL-VPN style HTTPS session"), that is unusually long
#   relative to an ordinary web request. This generalizes to a different
#   source IP or capture without needing to be re-hardcoded.
#
set -uo pipefail
# Deliberately not using -e: several tshark/grep/whois calls below are
# expected to return no matches or fail (e.g. no network access for whois),
# which makes them exit non-zero on some systems. Every value is checked
# and defaulted instead of letting the script die.

VPN_DEST_PORT=443   # SSL-VPN / clientless VPN gateway port assumed by this task's brief

PCAP="${1:-}"
OUTFILE="vpn_pivot_findings.json"

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <full_timeline.pcap>" >&2
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

HAVE_PYTHON3=0
command -v python3 >/dev/null 2>&1 && HAVE_PYTHON3=1
HAVE_WHOIS=0
command -v whois >/dev/null 2>&1 && HAVE_WHOIS=1

fmt_time() {
    awk -v t="$1" 'BEGIN{
        if (t=="" ) { print "n/a"; exit }
        cmd = "date -u -d @" t " +\"%Y-%m-%d %H:%M:%S\" 2>/dev/null"
        cmd | getline out
        close(cmd)
        if (out=="") { printf "%.3f (epoch)", t } else { print out }
    }'
}

is_private_ip() {
    # is_private_ip <ip> -> 0 (true) if RFC1918, 1 (false) otherwise
    local ip="$1"
    case "$ip" in
        10.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
        192.168.*) return 0 ;;
        *) return 1 ;;
    esac
}

echo "\$ ./5-vpn_pivot.sh $PCAP"
echo ""

# ---------------------------------------------------------------------------
# 1. Identify the VPN connection
#    Command: tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==443" \
#             -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
#    Candidates are then filtered in-script to source IPs that are NOT
#    RFC1918 (public) connecting to a destination IP that IS RFC1918
#    (internal) — see header note above.
# ---------------------------------------------------------------------------

CANDIDATES=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==$VPN_DEST_PORT" \
    -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport 2>/dev/null)

VPN_TS=""
VPN_SRC_IP=""
VPN_SRC_PORT=""
VPN_DST_IP=""
while IFS=$'\t' read -r ts src sport dst _dport; do
    [ -z "$ts" ] && continue
    if ! is_private_ip "$src" && is_private_ip "$dst"; then
        VPN_TS="$ts"; VPN_SRC_IP="$src"; VPN_SRC_PORT="$sport"; VPN_DST_IP="$dst"
        break
    fi
done <<< "$CANDIDATES"

echo "=== VPN CONNECTION IDENTIFIED ==="
if [ -z "$VPN_TS" ]; then
    echo "No TCP session was found matching a public-source -> private-destination"
    echo "pattern on port $VPN_DEST_PORT in this capture. If the VPN gateway uses a"
    echo "different port (e.g. 1194 for OpenVPN, 500/4500 for IPsec), re-run this"
    echo "script with VPN_DEST_PORT edited accordingly, or inspect the capture"
    echo "manually to confirm the actual port in use before concluding there is no"
    echo "VPN pivot in this file."
    echo ""
else
    echo "Timestamp: $(fmt_time "$VPN_TS")"
    printf "Source: %s:%s\n" "$VPN_SRC_IP" "$VPN_SRC_PORT"
    printf "Destination: %s:%s\n" "$VPN_DST_IP" "$VPN_DEST_PORT"

    # Protocol characterization: look for a TLS ClientHello on this exact
    # session to confirm it is an SSL/TLS-based (SSL-VPN style) session
    # rather than plain unencrypted traffic that happens to use port 443.
    TLS_CH=$(tshark -r "$PCAP" -Y "tls.handshake.type==1 && ip.src==$VPN_SRC_IP && ip.dst==$VPN_DST_IP" \
        -T fields -e frame.time_epoch 2>/dev/null | head -1)
    if [ -n "$TLS_CH" ]; then
        echo "Protocol: TLS/SSL session on port $VPN_DEST_PORT (ClientHello observed) — consistent with an SSL-VPN style HTTPS session"
    else
        echo "Protocol: TCP session on port $VPN_DEST_PORT — no TLS ClientHello found, so this cannot be confirmed as an SSL/TLS session from packet evidence alone"
    fi

    # Authentication context: search for a readable account-name marker
    # within this session's packets. Several other captures in this module
    # embed a readable marker string instead of a real encrypted blob (see
    # Tasks 1 and 3), so the same generic text search is tried here, then
    # the matching frame's hex payload is decoded to extract the full
    # marker line (not just confirm the substring is present) whenever
    # python3 is available. If nothing is found, that is reported plainly
    # rather than assumed.
    AUTH_FRAME=$(tshark -r "$PCAP" -Y "frame contains \"dmarsh\" && ip.addr==$VPN_SRC_IP && ip.addr==$VPN_DST_IP" \
        -T fields -e frame.number -e frame.time_epoch 2>/dev/null | head -1)
    if [ -n "$AUTH_FRAME" ]; then
        AUTH_TS=$(echo "$AUTH_FRAME" | awk -F'\t' '{print $2}')
        AUTH_FNUM=$(echo "$AUTH_FRAME" | awk -F'\t' '{print $1}')
        AUTH_LINE=""
        if [ "$HAVE_PYTHON3" -eq 1 ]; then
            AUTH_HEX=$(tshark -r "$PCAP" -Y "frame.number==$AUTH_FNUM" -T fields -e tcp.payload 2>/dev/null | tr -d ':')
            if [ -n "$AUTH_HEX" ]; then
                AUTH_LINE=$(python3 -c '
import sys, re
h = sys.stdin.read().strip()
try:
    b = bytes.fromhex(h)
except ValueError:
    sys.exit(0)
s = b.decode("latin1", errors="replace")
m = re.search(r"[A-Za-z0-9_.-]+:user=[^\r\n\x00]+", s)
if m:
    print(m.group(0))
' <<< "$AUTH_HEX")
            fi
        fi
        if [ -n "$AUTH_LINE" ]; then
            echo "Authentication context: a readable marker was found in this session's packet data at $(fmt_time "$AUTH_TS") (frame $AUTH_FNUM): \"$AUTH_LINE\" — consistent with (but not conclusive proof of) credential use in this VPN session. Any password field in this marker is treated as sensitive and is not reproduced further than what the capture itself already shows in plaintext."
        else
            echo "Authentication context: the string \"dmarsh\" was found in this session's packet data at $(fmt_time "$AUTH_TS") (frame $AUTH_FNUM), but the surrounding marker line could not be decoded — consistent with (but not conclusive proof of) credential use in this VPN session"
        fi
    else
        echo "Authentication context: no readable account-name string was found in this session's packet data. If the VPN session is genuinely encrypted end-to-end, this is expected — account identity cannot be read from ciphertext, and this script does not claim otherwise."
    fi

    # 4. Session duration: last packet in the same TCP session (by IP pair
    #    and matching ports), via FIN/RST or simply the last observed packet.
    LAST_TS=$(tshark -r "$PCAP" -Y "ip.addr==$VPN_SRC_IP && ip.addr==$VPN_DST_IP && tcp.port==$VPN_SRC_PORT" \
        -T fields -e frame.time_epoch 2>/dev/null | sort -n | tail -1)
    CLOSE_TS="$LAST_TS"
    CLOSE_KIND="last observed packet in this session (no explicit FIN/RST distinguished)"
    FIN_TS=$(tshark -r "$PCAP" -Y "(tcp.flags.fin==1 || tcp.flags.reset==1) && ip.addr==$VPN_SRC_IP && ip.addr==$VPN_DST_IP && tcp.port==$VPN_SRC_PORT" \
        -T fields -e frame.time_epoch 2>/dev/null | sort -n | tail -1)
    if [ -n "$FIN_TS" ]; then
        CLOSE_TS="$FIN_TS"
        CLOSE_KIND="explicit FIN/RST close"
    fi

    DURATION_SEC=$(awk -v a="$VPN_TS" -v b="$CLOSE_TS" 'BEGIN{ if(a=="" || b=="") print ""; else printf "%.0f", b-a }')
    if [ -n "$DURATION_SEC" ]; then
        DURATION_MIN=$(awk -v s="$DURATION_SEC" 'BEGIN{printf "%.0f", s/60}')
        echo "Session duration: approximately ${DURATION_MIN} minutes (${DURATION_SEC} seconds, based on $CLOSE_KIND)"
    else
        echo "Session duration: could not be determined (no close event found for this session)"
    fi

    # 5. Assigned internal IP — heuristic: the first previously-unseen
    #    internal (RFC1918) source IP that begins sending traffic within
    #    5 minutes after the VPN connection starts, and that never
    #    appeared as a source before that timestamp. Reported as a
    #    CANDIDATE, not an asserted fact, since this is inferred rather
    #    than read directly from an "assigned IP" field. The VPN gateway's
    #    own destination IP ($VPN_DST_IP) is excluded from this search:
    #    it is the always-present VPN endpoint, not an address handed out
    #    to the connecting client, so it would otherwise falsely match as
    #    "new" the first time the gateway replies.
    WINDOW_END=$(awk -v t="$VPN_TS" 'BEGIN{print t+300}')
    ALL_SRC_BEFORE=$(tshark -r "$PCAP" -Y "frame.time_epoch < $VPN_TS" -T fields -e ip.src 2>/dev/null | sort -u)
    NEW_INTERNAL_SRC=$(tshark -r "$PCAP" -Y "frame.time_epoch >= $VPN_TS && frame.time_epoch <= $WINDOW_END" \
        -T fields -e frame.time_epoch -e ip.src 2>/dev/null \
        | while IFS=$'\t' read -r ts ip; do
            is_private_ip "$ip" || continue
            [ "$ip" = "$VPN_DST_IP" ] && continue
            echo "$ALL_SRC_BEFORE" | grep -qx "$ip" && continue
            echo "$ts	$ip"
          done | sort -n | head -1)
    if [ -n "$NEW_INTERNAL_SRC" ]; then
        NEW_IP=$(echo "$NEW_INTERNAL_SRC" | awk -F'\t' '{print $2}')
        echo "Assigned internal IP (candidate): $NEW_IP — first previously-unseen internal source IP active within 5 minutes of VPN connection start. Treat as a lead to confirm against DHCP/VPN pool logs, not a packet-proven assignment."
    else
        echo "Assigned internal IP: no previously-unseen internal source IP appeared within 5 minutes of the VPN connection start — no candidate identified from this heuristic."
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# 2. Geolocate the source IP
#    Command: whois -h whois.cymru.com " -v <ip>"   (ASN + country, one line)
#    Command: whois <ip>                            (organization / netname)
# ---------------------------------------------------------------------------

echo "=== GEOLOCATION ==="
if [ -z "$VPN_SRC_IP" ]; then
    echo "No VPN source IP identified above — skipping geolocation."
elif [ "$HAVE_WHOIS" -eq 0 ]; then
    echo "IP: $VPN_SRC_IP"
    echo "whois command not found on this machine — install it (apt install whois) to enable this lookup."
else
    echo "IP: $VPN_SRC_IP"
    CYMRU_LINE=$(timeout 8 whois -h whois.cymru.com " -v $VPN_SRC_IP" 2>/dev/null | tail -1)
    if [ -n "$CYMRU_LINE" ] && echo "$CYMRU_LINE" | grep -q '|'; then
        ASN=$(echo "$CYMRU_LINE" | awk -F'|' '{gsub(/^ +| +$/,"",$1); print $1}')
        CC=$(echo "$CYMRU_LINE" | awk -F'|' '{gsub(/^ +| +$/,"",$4); print $4}')
        AS_NAME=$(echo "$CYMRU_LINE" | awk -F'|' '{gsub(/^ +| +$/,"",$7); print $7}')
        echo "ASN: AS${ASN}"
        echo "Country code: ${CC}"
        echo "AS Name / Organization: ${AS_NAME}"
    else
        echo "ASN/country lookup (Team Cymru whois) failed or timed out — no network access, or the query was blocked. Re-run this on a machine with outbound network access to whois.cymru.com (port 43) to get a live result."
    fi

    WHOIS_FULL=$(timeout 8 whois "$VPN_SRC_IP" 2>/dev/null)
    if [ -n "$WHOIS_FULL" ]; then
        ORG_LINE=$(echo "$WHOIS_FULL" | grep -iE '^(OrgName|org-name|descr|netname):' | head -1)
        [ -n "$ORG_LINE" ] && echo "Registry detail: $ORG_LINE"
    fi

    echo "Assessment: geographic/ASN unusualness must be judged against where MedDefense"
    echo "actually expects remote-access connections from (e.g. known VPN client base,"
    echo "employee travel patterns) — this script reports the lookup result, not a"
    echo "verdict, since 'expected or anomalous' depends on organizational context this"
    echo "script does not have access to."
fi
echo ""

# ---------------------------------------------------------------------------
# 3. Correlate the VPN timestamp with the lateral movement timeline
#    Command: tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==3389" \
#            -T fields -e frame.time_epoch -e ip.src -e ip.dst
#    RDP (port 3389) is detected directly in this same capture rather than
#    by parsing 4-lateral_movement.sh's JSON output: that file only records
#    an event in success_events/denied_events when a definite result was
#    seen, so an RDP attempt whose result is not visible at the packet
#    level (e.g. NLA-encrypted logon) would be silently missing from it.
#    Reading the RDP SYN directly from the packets is self-contained and
#    does not depend on another script's output shape.
# ---------------------------------------------------------------------------

echo "=== TIMELINE CORRELATION ==="
if [ -z "$VPN_TS" ]; then
    echo "No VPN connection identified above — skipping timeline correlation."
else
    echo "VPN connection:       $(fmt_time "$VPN_TS")"
    RDP_TS=$(tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==3389" \
        -T fields -e frame.time_epoch 2>/dev/null | sort -n | head -1)
    if [ -z "$RDP_TS" ]; then
        echo "First RDP movement:   no RDP (port 3389) connection attempt found in this capture — cannot compute a gap."
    else
        echo "First RDP movement:   $(fmt_time "$RDP_TS")"
        GAP_SEC=$(awk -v a="$VPN_TS" -v b="$RDP_TS" 'BEGIN{printf "%.0f", b-a}')
        if [ "$GAP_SEC" -ge 0 ] 2>/dev/null; then
            GAP_MIN=$(awk -v s="$GAP_SEC" 'BEGIN{printf "%.0f", s/60}')
            echo "Gap: approximately ${GAP_MIN} minutes (${GAP_SEC} seconds) between VPN connection start and the first RDP attempt"
        else
            echo "Gap: the first RDP attempt occurs BEFORE the identified VPN connection (${GAP_SEC} seconds) — this VPN session is not a plausible predecessor to that RDP activity; check for an earlier VPN/remote-access session in this capture."
        fi
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Pivot assessment + limitations
# ---------------------------------------------------------------------------

echo "=== PIVOT ASSESSMENT ==="
if [ -n "$VPN_TS" ]; then
    echo "A public-source, TLS-wrapped session to an internal gateway IP on port"
    echo "$VPN_DEST_PORT was found before this script's other lateral-movement evidence"
    echo "(see TIMELINE CORRELATION above). This is consistent with a VPN pivot"
    echo "bridging external credential use and internal activity, but the ordering"
    echo "and gap should be confirmed against the exact dates in your evidence,"
    echo "not assumed from time-of-day alone."
else
    echo "No VPN session was identified in this capture — no pivot assessment can be made."
fi
echo ""

echo "=== LIMITATIONS ==="
echo "This PCAP can prove: that a TCP/TLS session existed between the identified"
echo "external and internal IPs, at the recorded timestamps, for the computed"
echo "duration, and (only if a readable marker was found above) that an account"
echo "name string appeared in that session's packet data."
echo ""
echo "This PCAP cannot prove, from packet evidence alone: the actual password or"
echo "credential contents (if the session is genuinely encrypted), that the person"
echo "typing the credentials was actually the attacker versus e.g. a compromised"
echo "VPN client used by someone else, or that the 'assigned internal IP' heuristic"
echo "above is a real DHCP/VPN pool assignment rather than coincidental timing."
echo "Any credential-use conclusion here is based on metadata, timing and account"
echo "context — not on decrypted payload content."
echo ""

# ---------------------------------------------------------------------------
# Persist findings to JSON
# ---------------------------------------------------------------------------

if [ "$HAVE_PYTHON3" -eq 1 ]; then
    python3 - "$PCAP" "$OUTFILE" "$VPN_TS" "$VPN_SRC_IP" "$VPN_SRC_PORT" "$VPN_DST_IP" <<'PYEOF'
import sys, json

pcap, outfile, vpn_ts, src_ip, src_port, dst_ip = sys.argv[1:7]
data = {
    "source_pcap": pcap,
    "generated_by": "5-vpn_pivot.sh",
    "vpn_connection": {
        "timestamp_epoch": vpn_ts or None,
        "source_ip": src_ip or None,
        "source_port": src_port or None,
        "destination_ip": dst_ip or None,
    },
    "notes": "Geolocation requires outbound whois access on the machine running this script. Assigned-internal-IP and timeline-gap figures are heuristic/candidate findings, not directly read fields, and are labeled as such in the console output."
}
with open(outfile, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print(f"FINDINGS SAVED: {outfile}")
PYEOF
else
    printf '{\n  "source_pcap": "%s",\n  "generated_by": "5-vpn_pivot.sh",\n  "note": "python3 unavailable - minimal JSON only"\n}\n' "$PCAP" > "$OUTFILE"
    echo "FINDINGS SAVED: $OUTFILE (minimal — python3 was unavailable)"
fi
