#!/bin/bash
#
# 6-kill_chain.sh
#
# MedDefense Health Systems — Wireshark Territory (Task 6: The Kill Chain
# Reconstruction)
#
# Purpose
#   Combines the evidence gathered across the individual PCAPs of this
#   module (phishing click, C2 beaconing, VPN pivot, lateral movement, DNS
#   exfiltration) into one chronological, MITRE ATT&CK-mapped incident
#   timeline, states the attacker's total dwell time, flags the points
#   where intervention could have broken the chain, and separates
#   confirmed packet evidence from analytical inference at every step.
#
#   This script uses tshark for all packet analysis. Wireshark's GUI is
#   for manual, exploratory investigation and is not part of this
#   automated deliverable.
#
# Usage
#   ./6-kill_chain.sh [phishing_click.pcap] [c2_beaconing.pcap] \
#                      [dns_exfil.pcap] [lateral_movement.pcap] \
#                      [full_timeline.pcap]
#   All five arguments are optional and default to the filenames above in
#   the current directory, so the script can be run with no arguments when
#   the five PCAPs are named as delivered.
#
#   An optional sixth input, a plain-text file describing the initial
#   phishing email (subject/recipient/send time, as established in the
#   4x00 Phishing Dissection module), is read from the path in the
#   PHISHING_EMAIL_CONTEXT environment variable if set, otherwise from
#   ./4x00_phishing_context.txt if present. Phase 1 of this timeline is
#   NOT packet evidence (no PCAP records an SMTP send in this module), so
#   it is only populated when that context file is supplied; otherwise
#   this script reports it as unavailable rather than inventing email
#   content, a sender, or a timestamp it cannot verify.
#
# Requirements
#   - tshark (Wireshark CLI) must be installed and on PATH.
#   - python3 for interval statistics (beaconing regularity) and for
#     final JSON output. If missing, those specific steps are skipped
#     with a stated reason rather than silently producing wrong numbers.
#
# Reproducibility note
#   Every measurement is produced by an explicit tshark command, printed
#   as a comment directly above the line that runs it. Where a PCAP
#   argument is missing or unreadable, the corresponding phase is marked
#   "not available in this run" instead of being filled with assumed or
#   remembered values — a phase's absence here means its source file was
#   not supplied to this run, not that the activity did not happen.
#
# Known indicators reused across phases
#   The domain/IP/host values below were each independently established
#   by this module's own earlier detection scripts (0-baseline_analysis.sh,
#   1-phishing_click.sh, 3-dns_tunnel.sh, 4-lateral_movement.sh,
#   5-vpn_pivot.sh) against real evidence, not assumed here. They are
#   reused so this script can correlate the same incident across capture
#   files, which is the point of a kill-chain reconstruction; they are not
#   used as a general-purpose detection blocklist for unrelated captures.
#
set -uo pipefail

PHISHING_DOMAIN="meddefense-portal.com"
C2_IP="91.234.99.107"                 # phishing portal / beaconing / C2 IP (Tasks 0, 1)
VPN_DEST_PORT=443
RDP_PORT=3389
ANOMALOUS_LABEL_LEN_THRESHOLD=20      # see 3-dns_tunnel.sh for the rationale

PHISHING_PCAP="${1:-phishing_click.pcap}"
BEACON_PCAP="${2:-c2_beaconing.pcap}"
DNS_PCAP="${3:-dns_exfil.pcap}"
LATERAL_PCAP="${4:-lateral_movement.pcap}"
TIMELINE_PCAP="${5:-full_timeline.pcap}"
EMAIL_CONTEXT="${PHISHING_EMAIL_CONTEXT:-4x00_phishing_context.txt}"

OUTFILE="kill_chain_findings.json"

if ! command -v tshark >/dev/null 2>&1; then
    echo "ERROR: tshark not found. Install Wireshark/tshark first (apt install tshark)." >&2
    exit 1
fi

HAVE_PYTHON3=0
command -v python3 >/dev/null 2>&1 && HAVE_PYTHON3=1

pcap_ok() { [ -n "${1:-}" ] && [ -f "$1" ]; }

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
    local ip="$1"
    case "$ip" in
        10.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
        192.168.*) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Collected findings for each phase, filled in below. A trailing "TS" var
# holds the phase's anchor epoch timestamp for dwell-time/period math, and
# is left empty when that phase could not be established from evidence.
# ---------------------------------------------------------------------------
P1_TS=""; P1_STATUS="not available in this run"; P1_EVIDENCE=""; P1_ACTION=""
P2_TS=""; P2_END_TS=""; P2_STATUS="not available in this run"; P2_LINES=()
P3_TS=""; P3_END_TS=""; P3_STATUS="not available in this run"; P3_LINES=()
P4_TS=""; P4_STATUS="not available in this run"; P4_LINES=()
P5_TS=""; P5_STATUS="not available in this run"; P5_LINES=()
P6_TS=""; P6_END_TS=""; P6_STATUS="not available in this run"; P6_LINES=()
P7_TS=""; P7_END_TS=""; P7_STATUS="not available in this run"; P7_LINES=()

# Host identifiers surfaced by phases 4/5, referenced later in the impact
# summary; pre-declared so `set -u` does not fail when their phase's PCAP
# is unavailable and the block that would normally set them never runs.
VPN_SRC=""; VPN_DST=""
RDP_SRC=""; RDP_DST=""
RST_N=""

# ---------------------------------------------------------------------------
# PHASE 1: INITIAL ACCESS (T1566.002 - Spearphishing Link)
#   Not packet evidence — read from an optional 4x00 context file only.
# ---------------------------------------------------------------------------
if [ -f "$EMAIL_CONTEXT" ]; then
    P1_STATUS="context from 4x00, not packet evidence"
    P1_EVIDENCE="$EMAIL_CONTEXT"
    P1_ACTION=$(head -5 "$EMAIL_CONTEXT" | tr '\n' ' ' | sed 's/  */ /g')
    P1_TS_RAW=$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}(:[0-9]{2})?' "$EMAIL_CONTEXT" | head -1)
    if [ -n "$P1_TS_RAW" ] && [ "$HAVE_PYTHON3" -eq 1 ]; then
        P1_TS=$(python3 -c "
import sys, datetime
s = '$P1_TS_RAW'.replace('T',' ')
for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
    try:
        print(datetime.datetime.strptime(s, fmt).replace(tzinfo=datetime.timezone.utc).timestamp())
        break
    except ValueError:
        continue
" 2>/dev/null)
    fi
fi

# ---------------------------------------------------------------------------
# PHASE 2: CREDENTIAL HARVESTING SESSION (T1056.003 - Web Portal Capture)
#   Command: tshark -r <pcap> -Y "dns.qry.name==<phishing domain>" \
#            -T fields -e frame.time_epoch
#   Command: tshark -r <pcap> -Y "tls.handshake.extensions_server_name==<domain>" \
#            -T fields -e frame.time_epoch -e tls.handshake.extensions_server_name
# ---------------------------------------------------------------------------
if pcap_ok "$PHISHING_PCAP"; then
    DNS_TS=$(tshark -r "$PHISHING_PCAP" -Y "dns.flags.response==0 && dns.qry.name==\"$PHISHING_DOMAIN\"" \
        -T fields -e frame.time_epoch 2>/dev/null | head -1)
    SNI_TS=$(tshark -r "$PHISHING_PCAP" -Y "tls.handshake.type==1 && tls.handshake.extensions_server_name==\"$PHISHING_DOMAIN\"" \
        -T fields -e frame.time_epoch 2>/dev/null | head -1)
    LAST_TS=$(tshark -r "$PHISHING_PCAP" -Y "tls.record.content_type==23" \
        -T fields -e frame.time_epoch 2>/dev/null | sort -n | tail -1)
    if [ -n "$DNS_TS" ] || [ -n "$SNI_TS" ]; then
        P2_TS="${DNS_TS:-$SNI_TS}"
        P2_END_TS="${LAST_TS:-$P2_TS}"
        P2_STATUS="confirmed packet evidence"
        [ -n "$DNS_TS" ] && P2_LINES+=("DNS query: $PHISHING_DOMAIN resolved at $(fmt_time "$DNS_TS")")
        [ -n "$SNI_TS" ] && P2_LINES+=("TLS SNI: $PHISHING_DOMAIN observed in ClientHello at $(fmt_time "$SNI_TS")")
        LARGEST=$(tshark -r "$PHISHING_PCAP" -Y "tls.record.content_type==23 && tls.record.length" \
            -T fields -e frame.time_epoch -e tls.record.length 2>/dev/null | sort -t$'\t' -k2 -n -r | head -1)
        if [ -n "$LARGEST" ]; then
            L_TS=$(echo "$LARGEST" | awk -F'\t' '{print $1}')
            L_LEN=$(echo "$LARGEST" | awk -F'\t' '{print $2}')
            P2_LINES+=("Largest TLS application-data record: ${L_LEN} bytes at $(fmt_time "$L_TS")")
        fi
    else
        P2_STATUS="PCAP present but no $PHISHING_DOMAIN activity found"
    fi
else
    P2_STATUS="not available in this run (PCAP not found: $PHISHING_PCAP)"
fi

# ---------------------------------------------------------------------------
# PHASE 3: BEACONING (T1071.001 - Web Protocols)
#   Command: tshark -r <pcap> -Y "tls.handshake.type==1 && ip.dst==<C2 IP>" \
#            -T fields -e frame.time_epoch -e ip.src
# ---------------------------------------------------------------------------
if pcap_ok "$BEACON_PCAP"; then
    SESSIONS=$(tshark -r "$BEACON_PCAP" -Y "tls.handshake.type==1 && ip.dst==$C2_IP" \
        -T fields -e frame.time_epoch -e ip.src 2>/dev/null | sort -n)
    N_SESSIONS=$(echo "$SESSIONS" | grep -c . || true)
    if [ "$N_SESSIONS" -gt 0 ]; then
        P3_TS=$(echo "$SESSIONS" | head -1 | awk -F'\t' '{print $1}')
        P3_END_TS=$(echo "$SESSIONS" | tail -1 | awk -F'\t' '{print $1}')
        SRC_IP=$(echo "$SESSIONS" | head -1 | awk -F'\t' '{print $2}')
        P3_STATUS="confirmed packet evidence"
        P3_LINES+=("$N_SESSIONS TLS sessions from $SRC_IP to $C2_IP between $(fmt_time "$P3_TS") and $(fmt_time "$P3_END_TS")")
        if [ "$HAVE_PYTHON3" -eq 1 ] && [ "$N_SESSIONS" -gt 2 ]; then
            INTERVAL_STATS=$(echo "$SESSIONS" | awk -F'\t' '{print $1}' | python3 -c '
import sys
ts = [float(x) for x in sys.stdin if x.strip()]
ts.sort()
gaps = [b-a for a,b in zip(ts, ts[1:])]
if gaps:
    mean = sum(gaps)/len(gaps)
    var = sum((g-mean)**2 for g in gaps)/len(gaps)
    print(f"{mean:.1f}\t{var**0.5:.1f}")
')
            if [ -n "$INTERVAL_STATS" ]; then
                MEAN_GAP=$(echo "$INTERVAL_STATS" | awk -F'\t' '{print $1}')
                STDEV_GAP=$(echo "$INTERVAL_STATS" | awk -F'\t' '{print $2}')
                P3_LINES+=("Interval: mean ${MEAN_GAP}s, stdev ${STDEV_GAP}s (low stdev relative to mean indicates automated, regular beaconing rather than human browsing)")
            fi
        fi
    else
        P3_STATUS="PCAP present but no TLS sessions to $C2_IP found"
    fi
else
    P3_STATUS="not available in this run (PCAP not found: $BEACON_PCAP)"
fi

# ---------------------------------------------------------------------------
# PHASE 4: EXTERNAL ACCESS / VPN PIVOT (T1133 - External Remote Services)
#   Command: tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==443" \
#            -T fields -e frame.time_epoch -e ip.src -e ip.dst
#   (Same detection approach as 5-vpn_pivot.sh: public source -> private
#   destination on the VPN-typical port, rather than a hardcoded IP.)
# ---------------------------------------------------------------------------
if pcap_ok "$TIMELINE_PCAP"; then
    CANDIDATES=$(tshark -r "$TIMELINE_PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==$VPN_DEST_PORT" \
        -T fields -e frame.time_epoch -e ip.src -e ip.dst 2>/dev/null)
    VPN_SRC=""; VPN_DST=""
    while IFS=$'\t' read -r ts src dst; do
        [ -z "$ts" ] && continue
        if ! is_private_ip "$src" && is_private_ip "$dst"; then
            P4_TS="$ts"; VPN_SRC="$src"; VPN_DST="$dst"
            break
        fi
    done <<< "$CANDIDATES"
    if [ -n "$P4_TS" ]; then
        P4_STATUS="confirmed packet evidence"
        P4_LINES+=("External VPN connection from $VPN_SRC to $VPN_DST at $(fmt_time "$P4_TS")")
        AUTH_HIT=$(tshark -r "$TIMELINE_PCAP" -Y "frame contains \"user=\" && ip.addr==$VPN_SRC && ip.addr==$VPN_DST" \
            -T fields -e frame.number 2>/dev/null | head -1)
        if [ -n "$AUTH_HIT" ]; then
            P4_LINES+=("Account context marker present in this session's packet data (frame $AUTH_HIT)")
        else
            P4_LINES+=("No readable account-name marker found in this session's packet data")
        fi
    else
        P4_STATUS="PCAP present but no public-source/private-destination session on port $VPN_DEST_PORT found"
    fi
else
    P4_STATUS="not available in this run (PCAP not found: $TIMELINE_PCAP)"
fi

# ---------------------------------------------------------------------------
# PHASE 5: LATERAL MOVEMENT (T1021.001 - Remote Desktop Protocol)
#   Command: tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==3389" \
#            -T fields -e frame.time_epoch -e ip.src -e ip.dst
# ---------------------------------------------------------------------------
RDP_SRC=""; RDP_DST=""
if pcap_ok "$LATERAL_PCAP"; then
    RDP_LINE=$(tshark -r "$LATERAL_PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==$RDP_PORT" \
        -T fields -e frame.time_epoch -e ip.src -e ip.dst 2>/dev/null | sort -n | head -1)
    if [ -n "$RDP_LINE" ]; then
        P5_TS=$(echo "$RDP_LINE" | awk -F'\t' '{print $1}')
        RDP_SRC=$(echo "$RDP_LINE" | awk -F'\t' '{print $2}')
        RDP_DST=$(echo "$RDP_LINE" | awk -F'\t' '{print $3}')
        P5_STATUS="confirmed packet evidence"
        P5_LINES+=("RDP connection attempt from $RDP_SRC to $RDP_DST at $(fmt_time "$P5_TS")")
        AUTH_HIT=$(tshark -r "$LATERAL_PCAP" -Y "frame contains \"user=\" && ip.addr==$RDP_SRC && ip.addr==$RDP_DST" \
            -T fields -e frame.number 2>/dev/null | head -1)
        if [ -n "$AUTH_HIT" ]; then
            P5_LINES+=("Account context marker present in this session's packet data (frame $AUTH_HIT)")
        else
            P5_LINES+=("Account identity not visible at packet level for this session (e.g. NLA-encrypted logon)")
        fi
    else
        P5_STATUS="PCAP present but no RDP (port $RDP_PORT) connection attempt found"
    fi
else
    P5_STATUS="not available in this run (PCAP not found: $LATERAL_PCAP)"
fi

# ---------------------------------------------------------------------------
# PHASE 6: DISCOVERY (T1135, T1083)
#   Command: tshark -r <pcap> -Y "smb2.cmd==3 || smb2.cmd==5 || smb2.cmd==14" \
#            -T fields -e frame.time_epoch -e smb2.cmd -e smb2.nt_status
# ---------------------------------------------------------------------------
if pcap_ok "$LATERAL_PCAP"; then
    SMB_LINES_RAW=$(tshark -r "$LATERAL_PCAP" -Y "smb2.cmd==3 || smb2.cmd==5 || smb2.cmd==14" \
        -T fields -e frame.time_epoch -e smb2.cmd -e smb2.nt_status 2>/dev/null | sort -n)
    N_SMB=$(echo "$SMB_LINES_RAW" | grep -c . || true)
    if [ "$N_SMB" -gt 0 ]; then
        P6_TS=$(echo "$SMB_LINES_RAW" | head -1 | awk -F'\t' '{print $1}')
        P6_END_TS=$(echo "$SMB_LINES_RAW" | tail -1 | awk -F'\t' '{print $1}')
        P6_STATUS="confirmed packet evidence"
        N_SUCCESS=$(echo "$SMB_LINES_RAW" | awk -F'\t' '$3=="0x00000000"' | grep -c . || true)
        N_DENIED=$(echo "$SMB_LINES_RAW" | awk -F'\t' '$3!="0x00000000" && $3!=""' | grep -c . || true)
        P6_LINES+=("$N_SMB SMB2 tree-connect/create/query-directory requests between $(fmt_time "$P6_TS") and $(fmt_time "$P6_END_TS")")
        P6_LINES+=("SUCCESS status: $N_SUCCESS, non-SUCCESS status (access denied or similar): $N_DENIED")
    else
        P6_STATUS="PCAP present but no SMB2 tree-connect/create/query-directory activity found"
    fi
    RST_N=$(tshark -r "$LATERAL_PCAP" -Y "tcp.flags.reset==1" -T fields -e frame.number 2>/dev/null | grep -c . || true)
    P6_LINES+=("TCP RST (refused/reset) packets observed in this capture: $RST_N")
else
    P6_STATUS="not available in this run (PCAP not found: $LATERAL_PCAP)"
fi

# ---------------------------------------------------------------------------
# PHASE 7: EXFILTRATION (T1048.003 - Exfiltration Over Alternative Protocol)
#   Command: tshark -r <pcap> -Y "dns.flags.response==0" \
#            -T fields -e frame.time_epoch -e dns.qry.name
#   Classification: query label length > threshold (see 3-dns_tunnel.sh).
# ---------------------------------------------------------------------------
if pcap_ok "$DNS_PCAP"; then
    ALL_Q=$(tshark -r "$DNS_PCAP" -Y "dns.flags.response==0" \
        -T fields -e frame.time_epoch -e dns.qry.name 2>/dev/null)
    ANOM=$(echo "$ALL_Q" | awk -F'\t' -v n="$ANOMALOUS_LABEL_LEN_THRESHOLD" '{
        split($2, parts, "."); if (length(parts[1]) > n) print $1
    }' | sort -n)
    N_ANOM=$(echo "$ANOM" | grep -c . || true)
    if [ "$N_ANOM" -gt 0 ]; then
        P7_TS=$(echo "$ANOM" | head -1)
        P7_END_TS=$(echo "$ANOM" | tail -1)
        P7_STATUS="confirmed packet evidence"
        P7_LINES+=("$N_ANOM anomalous DNS queries (label length > $ANOMALOUS_LABEL_LEN_THRESHOLD chars) between $(fmt_time "$P7_TS") and $(fmt_time "$P7_END_TS")")
    else
        P7_STATUS="PCAP present but no anomalous-length DNS queries found"
    fi
else
    P7_STATUS="not available in this run (PCAP not found: $DNS_PCAP)"
fi

# ---------------------------------------------------------------------------
# Aggregate period / dwell time from whichever phase timestamps were found
# ---------------------------------------------------------------------------
ALL_TS=()
for t in "$P1_TS" "$P2_TS" "$P2_END_TS" "$P3_TS" "$P3_END_TS" "$P4_TS" "$P5_TS" "$P6_TS" "$P6_END_TS" "$P7_TS" "$P7_END_TS"; do
    [ -n "$t" ] && ALL_TS+=("$t")
done

PERIOD_START=""; PERIOD_END=""; DWELL_STR="not computable — fewer than two dated phases available"
if [ "${#ALL_TS[@]}" -ge 2 ]; then
    PERIOD_START=$(printf '%s\n' "${ALL_TS[@]}" | sort -n | head -1)
    PERIOD_END=$(printf '%s\n' "${ALL_TS[@]}" | sort -n | tail -1)
    DWELL_SEC=$(awk -v a="$PERIOD_START" -v b="$PERIOD_END" 'BEGIN{printf "%.0f", b-a}')
    DWELL_STR=$(awk -v s="$DWELL_SEC" 'BEGIN{
        h=int(s/3600); m=int((s%3600)/60);
        printf "approximately %d hours, %d minutes", h, m
    }')
fi

# ---------------------------------------------------------------------------
# Print the reconstruction
# ---------------------------------------------------------------------------
echo "$ ./6-kill_chain.sh"
echo ""
echo "================================================================"
echo "   COMPLETE KILL CHAIN RECONSTRUCTION"
echo "   Incident: Phishing Campaign -> Network Compromise -> DNS Exfiltration"
if [ -n "$PERIOD_START" ]; then
    echo "   Period: $(fmt_time "$PERIOD_START") to $(fmt_time "$PERIOD_END")"
    echo "   Dwell time: $DWELL_STR"
else
    echo "   Period: not computable — fewer than two of the five/six source files were available in this run"
fi
echo "================================================================"
echo ""

echo "PHASE 1: INITIAL ACCESS (T1566.002 - Spearphishing Link)"
if [ -n "$P1_ACTION" ]; then
    echo "  Time: $(fmt_time "$P1_TS")"
    echo "  Evidence: $P1_EVIDENCE"
    echo "  Action: $P1_ACTION"
fi
echo "  Status: $P1_STATUS"
echo ""

echo "PHASE 2: CREDENTIAL HARVESTING SESSION (T1056.003 - Web Portal Capture)"
echo "  Time: $(fmt_time "$P2_TS") to $(fmt_time "$P2_END_TS")"
echo "  Evidence: $PHISHING_PCAP"
if [ "${#P2_LINES[@]}" -gt 0 ]; then
    echo "  Packet evidence:"
    for l in "${P2_LINES[@]}"; do echo "    $l"; done
fi
echo "  Status: $P2_STATUS"
echo "  Assessment: encrypted session metadata is consistent with form submission; decrypted form contents are not visible in this capture (analytical inference, not confirmed content)."
echo ""

echo "PHASE 3: BEACONING (T1071.001 - Web Protocols)"
echo "  Time: $(fmt_time "$P3_TS") to $(fmt_time "$P3_END_TS")"
echo "  Evidence: $BEACON_PCAP"
if [ "${#P3_LINES[@]}" -gt 0 ]; then
    echo "  Packet evidence:"
    for l in "${P3_LINES[@]}"; do echo "    $l"; done
fi
echo "  Status: $P3_STATUS"
echo ""

echo "PHASE 4: EXTERNAL ACCESS / VPN PIVOT (T1133 - External Remote Services)"
echo "  Time: $(fmt_time "$P4_TS")"
echo "  Evidence: $TIMELINE_PCAP"
if [ "${#P4_LINES[@]}" -gt 0 ]; then
    echo "  Packet evidence:"
    for l in "${P4_LINES[@]}"; do echo "    $l"; done
fi
echo "  Status: $P4_STATUS"
if [ -n "$P4_TS" ] && [ -n "$P5_TS" ]; then
    GAP=$(awk -v a="$P4_TS" -v b="$P5_TS" 'BEGIN{printf "%.0f", (b-a)/60}')
    echo "  Assessment: VPN activity precedes the first lateral-movement attempt by approximately ${GAP} minutes."
fi
echo ""

echo "PHASE 5: LATERAL MOVEMENT (T1021.001 - Remote Desktop Protocol)"
echo "  Time: $(fmt_time "$P5_TS")"
echo "  Evidence: $LATERAL_PCAP"
if [ "${#P5_LINES[@]}" -gt 0 ]; then
    echo "  Packet evidence:"
    for l in "${P5_LINES[@]}"; do echo "    $l"; done
fi
echo "  Status: $P5_STATUS"
echo ""

echo "PHASE 6: DISCOVERY (T1135, T1083)"
echo "  Time: $(fmt_time "$P6_TS") to $(fmt_time "$P6_END_TS")"
echo "  Evidence: $LATERAL_PCAP"
if [ "${#P6_LINES[@]}" -gt 0 ]; then
    echo "  Packet evidence:"
    for l in "${P6_LINES[@]}"; do echo "    $l"; done
fi
echo "  Status: $P6_STATUS"
echo ""

echo "PHASE 7: EXFILTRATION (T1048.003 - Exfiltration Over Alternative Protocol)"
echo "  Time: $(fmt_time "$P7_TS") to $(fmt_time "$P7_END_TS")"
echo "  Evidence: $DNS_PCAP"
if [ "${#P7_LINES[@]}" -gt 0 ]; then
    echo "  Packet evidence:"
    for l in "${P7_LINES[@]}"; do echo "    $l"; done
fi
echo "  Status: $P7_STATUS"
echo ""

echo "=== VISIBILITY / DEFENSE SCORECARD ==="
echo "HELD / RESISTED:"
HELD_ANY=0
if [ "$P6_STATUS" = "confirmed packet evidence" ]; then
    echo "  Access denied / non-SUCCESS responses observed on some internal SMB targets"
    HELD_ANY=1
fi
if pcap_ok "$LATERAL_PCAP" && [ "${RST_N:-0}" -gt 0 ] 2>/dev/null; then
    echo "  Refused or reset (TCP RST) connections observed toward restricted internal systems"
    HELD_ANY=1
fi
[ "$HELD_ANY" -eq 0 ] && echo "  (none confirmed from the evidence available in this run)"
echo ""
echo "FAILED OR BYPASSED:"
[ "$P2_STATUS" = "confirmed packet evidence" ] && echo "  User traffic reached the phishing domain ($PHISHING_DOMAIN)"
[ "$P4_STATUS" = "confirmed packet evidence" ] && echo "  Valid-looking credentials appear to have enabled external VPN access"
[ "$P5_STATUS" = "confirmed packet evidence" ] && echo "  RDP connection from an internal workstation to a server system was attempted/established"
[ "$P7_STATUS" = "confirmed packet evidence" ] && echo "  DNS TXT tunnel activity was present in packet evidence"
echo ""
echo "ABSENT OR UNCONFIRMED FROM PCAP ALONE:"
echo "  Whether endpoint malware executed"
echo "  Whether MFA was enabled or disabled"
echo "  Whether alerts fired in any SIEM or monitoring system"
echo "  Exact plaintext credentials or the full content of exfiltrated data"
echo ""

echo "=== IMPACT ASSESSMENT ==="
SYSTEMS=()
[ -n "$VPN_DST" ] && SYSTEMS+=("$VPN_DST (VPN endpoint)")
[ -n "$RDP_SRC" ] && SYSTEMS+=("$RDP_SRC")
[ -n "$RDP_DST" ] && SYSTEMS+=("$RDP_DST")
if [ "${#SYSTEMS[@]}" -gt 0 ]; then
    echo "Systems involved (from packet evidence): $(printf '%s, ' "${SYSTEMS[@]}" | sed 's/, $//')"
else
    echo "Systems involved: not determinable — no phase in this run produced host-level evidence"
fi
if [ "$P7_STATUS" = "confirmed packet evidence" ]; then
    echo "Data likely exfiltrated: structured data over a DNS TXT tunnel (exact content unconfirmed from metadata alone — see 3-dns_tunnel.sh for any decoded fragments)"
else
    echo "Data likely exfiltrated: unconfirmed — no DNS exfiltration evidence available in this run"
fi
echo "Systems resisted access: see VISIBILITY / DEFENSE SCORECARD above"
echo "Blast radius: bounded by the systems named above; this script does not extrapolate beyond what packet evidence supports"
echo ""

echo "=== CRITICAL PIVOT POINTS ==="
[ "$P2_STATUS" = "confirmed packet evidence" ] && echo "  Blocking or warning on the phishing domain ($PHISHING_DOMAIN) at DNS/proxy layer would have prevented credential harvesting"
[ "$P4_STATUS" = "confirmed packet evidence" ] && echo "  Requiring MFA or geofencing on the VPN gateway is where stolen credentials were first used operationally"
[ "$P5_STATUS" = "confirmed packet evidence" ] && echo "  Restricting RDP between workstation and server subnets would have blocked this lateral-movement path"
[ "$P7_STATUS" = "confirmed packet evidence" ] && echo "  DNS query-length/entropy monitoring would have flagged the exfiltration channel while it was active"
echo ""

echo "=== EVIDENCE VS INFERENCE ==="
echo "Confirmed packet evidence: timestamps, source/destination IPs and ports, DNS"
echo "queries, TLS handshake metadata, and any plaintext marker strings shown above"
echo "exactly as extracted by the tshark commands documented in this script."
echo "Analytical inference: which phase 'caused' the next (e.g. that the phishing"
echo "click led to the credential used in the VPN session), impact/blast-radius"
echo "judgments, and any assessment phrased as 'consistent with' or 'suggests'."
echo "These connect the evidence into a narrative but are not directly recorded in"
echo "any single packet."
echo ""

# ---------------------------------------------------------------------------
# Persist findings to JSON
# ---------------------------------------------------------------------------
if [ "$HAVE_PYTHON3" -eq 1 ]; then
    python3 - "$OUTFILE" "$PERIOD_START" "$PERIOD_END" \
        "$P1_STATUS" "$P2_STATUS" "$P3_STATUS" "$P4_STATUS" "$P5_STATUS" "$P6_STATUS" "$P7_STATUS" <<'PYEOF'
import sys, json

outfile, period_start, period_end = sys.argv[1:4]
statuses = sys.argv[4:11]
labels = ["initial_access", "credential_harvesting", "beaconing",
          "vpn_pivot", "lateral_movement", "discovery", "exfiltration"]
data = {
    "generated_by": "6-kill_chain.sh",
    "period_start_epoch": period_start or None,
    "period_end_epoch": period_end or None,
    "phase_status": dict(zip(labels, statuses)),
    "notes": "Each phase's status field distinguishes 'confirmed packet evidence', 'PCAP present but no matching activity found', and 'not available in this run' (source file missing). Phase 1 is never packet evidence by design, since no PCAP in this module records SMTP delivery."
}
with open(outfile, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print(f"FINDINGS SAVED: {outfile}")
PYEOF
else
    printf '{\n  "generated_by": "6-kill_chain.sh",\n  "note": "python3 unavailable - minimal JSON only"\n}\n' > "$OUTFILE"
    echo "FINDINGS SAVED: $OUTFILE (minimal — python3 was unavailable)"
fi
