#!/bin/bash
#
# 8-evidence_crosscheck.sh
#
# MedDefense Health Systems — Wireshark Territory (Task 8: The Evidence
# Cross-Check)
#
# Purpose
#   Compares the kill-chain narrative (Task 6) against what the PCAPs of
#   this module actually prove, for each phase: what is CONFIRMED by
#   packet evidence, what is only a STRONG INFERENCE from timing/context,
#   what is UNCONFIRMED, and what is NOT VISIBLE IN PCAP at all — plus
#   what additional evidence source would be needed to close each gap,
#   and an overall packet-visibility score.
#
#   This script has no PCAP input and runs no tshark commands directly.
#   It instead reads kill_chain_findings.json (produced by
#   6-kill_chain.sh) when present next to it, to base the "does direct
#   PCAP evidence exist for this phase?" column on that run's actual
#   result rather than on a fixed assumption. If that file is not found,
#   it falls back to the phase-evidence status already established by
#   real tshark testing earlier in this module (Tasks 0, 1, 3, 4, 5 and
#   6 of this project) — that fallback is stated explicitly below and in
#   the script's output, so a reader always knows whether a given phase's
#   "evidence exists" answer came from a fresh run or from this module's
#   prior confirmed results.
#
#   Note on Phase 6 (Discovery/SMB): earlier real testing in this module
#   (4-lateral_movement.sh run against the user's own lateral_movement
#   capture, and 6-kill_chain.sh run against full_timeline.pcap) found NO
#   SMB2 tree-connect/create/query-directory activity in this incident's
#   actual PCAPs. This script reports that honestly as NOT VISIBLE IN
#   PCAP rather than assuming SMB enumeration occurred just because a
#   generic investigation narrative would expect it — overclaiming
#   evidence that is not there is exactly the mistake this task exists to
#   avoid.
#
# Usage
#   ./8-evidence_crosscheck.sh [kill_chain_findings.json]
#
set -uo pipefail

KILL_CHAIN_JSON="${1:-kill_chain_findings.json}"
HAVE_PYTHON3=0
command -v python3 >/dev/null 2>&1 && HAVE_PYTHON3=1

# ---------------------------------------------------------------------------
# Determine, per phase, whether direct PCAP evidence exists.
# Default values reflect this module's own real, previously-confirmed
# results (see header note); JSON_SOURCE tracks whether that default was
# overridden by a fresh kill_chain_findings.json read.
# ---------------------------------------------------------------------------
declare -A EVIDENCE=(
    [1]="no"    # initial access: never packet evidence, no PCAP in this module records SMTP delivery
    [2]="yes"   # credential harvesting: DNS + TLS SNI confirmed (1-phishing_click.sh, real PCAP)
    [3]="yes"   # beaconing: 24 TLS sessions, ~300s interval confirmed (6-kill_chain.sh, real c2_beaconing.pcap)
    [4]="yes"   # VPN pivot: external->internal TLS session confirmed (5-vpn_pivot.sh, real full_timeline.pcap)
    [5]="yes"   # RDP lateral movement: RDP SYN confirmed (4-lateral_movement.sh / 6-kill_chain.sh, real PCAP)
    [6]="no"    # SMB discovery: NOT found in this module's real captures (see header note)
    [7]="yes"   # DNS exfiltration: anomalous TXT tunnel confirmed and partially decoded (3-dns_tunnel.sh, real PCAP)
)
JSON_SOURCE="fallback (this module's previously-confirmed real tshark results — see header note)"

if [ -f "$KILL_CHAIN_JSON" ] && [ "$HAVE_PYTHON3" -eq 1 ]; then
    JSON_LINE=$(python3 -c "
import json, sys
try:
    data = json.load(open('$KILL_CHAIN_JSON'))
except Exception:
    sys.exit(1)
status = data.get('phase_status', {})
order = ['initial_access', 'credential_harvesting', 'beaconing', 'vpn_pivot',
          'lateral_movement', 'discovery', 'exfiltration']
out = []
for key in order:
    v = status.get(key, '')
    out.append('yes' if v == 'confirmed packet evidence' else 'no')
print(','.join(out))
" 2>/dev/null)
    if [ -n "$JSON_LINE" ]; then
        IFS=',' read -r E1 E2 E3 E4 E5 E6 E7 <<< "$JSON_LINE"
        EVIDENCE[1]="$E1"; EVIDENCE[2]="$E2"; EVIDENCE[3]="$E3"; EVIDENCE[4]="$E4"
        EVIDENCE[5]="$E5"; EVIDENCE[6]="$E6"; EVIDENCE[7]="$E7"
        JSON_SOURCE="$KILL_CHAIN_JSON (live read from this run)"
    fi
fi

LABELS=(
    "Phishing delivery"
    "Credential harvest"
    "C2 beaconing"
    "VPN pivot"
    "RDP lateral movement"
    "SMB discovery"
    "DNS exfiltration"
)

# Verdict per phase: phase 1 is a fixed special case (context, not PCAP).
# For phases 2-7, the verdict when evidence="yes" reflects what that TYPE
# of packet evidence can and cannot establish (e.g. a TLS session proves
# communication occurred, not what was typed into an encrypted form) —
# this reasoning holds regardless of which specific run produced the
# evidence, so it is fixed per phase rather than re-derived from the JSON.
declare -A VERDICT_IF_YES=(
    [2]="STRONG INFERENCE"
    [3]="CONFIRMED"
    [4]="STRONG INFERENCE"
    [5]="CONFIRMED"
    [6]="CONFIRMED"
    [7]="CONFIRMED"
)

echo "\$ ./8-evidence_crosscheck.sh"
echo ""
echo "================================================================"
echo "   EVIDENCE CROSS-CHECK - PCAP VISIBILITY"
echo "================================================================"
echo ""
echo "Phase | Attack Action         | PCAP Evidence? | Verdict"
echo "------|------------------------|----------------|------------------"

YES_COUNT=0
for i in 1 2 3 4 5 6 7; do
    label="${LABELS[$((i-1))]}"
    ev="${EVIDENCE[$i]}"
    if [ "$i" -eq 1 ]; then
        ev_display="No"
        verdict="4x00 CONTEXT"
    elif [ "$ev" = "yes" ]; then
        ev_display="Yes"
        verdict="${VERDICT_IF_YES[$i]}"
        YES_COUNT=$((YES_COUNT + 1))
    else
        ev_display="No"
        verdict="NOT VISIBLE IN PCAP"
    fi
    printf "  %d   | %-22s | %-14s | %s\n" "$i" "$label" "$ev_display" "$verdict"
done
echo ""
echo "(PCAP-evidence column source: $JSON_SOURCE)"
echo ""

echo "=== CONFIRMED FROM PCAP ==="
[ "${EVIDENCE[2]}" = "yes" ] && echo "- DNS query for meddefense-portal.com and TLS SNI to the same domain"
[ "${EVIDENCE[3]}" = "yes" ] && echo "- Repeated ~300-second HTTPS beaconing pattern to 91.234.99.107"
[ "${EVIDENCE[4]}" = "yes" ] && echo "- TCP/TLS session from an external IP (154.118.42.89) to an internal VPN endpoint"
[ "${EVIDENCE[5]}" = "yes" ] && echo "- RDP (TCP/3389) session from a clinical workstation to a server-subnet host"
if [ "${EVIDENCE[6]}" = "yes" ]; then
    echo "- SMB enumeration activity (SMB2 tree-connect/create/query-directory requests)"
fi
[ "${EVIDENCE[7]}" = "yes" ] && echo "- DNS TXT queries with encoded, oversized leftmost labels, consistent with tunneling"
echo ""

echo "=== STRONG INFERENCE ==="
[ "${EVIDENCE[2]}" = "yes" ] && echo "- Credential submission through the phishing page (TLS-encrypted form data; content not visible)"
[ "${EVIDENCE[4]}" = "yes" ] && echo "- Use of a specific account's credentials for VPN access (account marker present in packet data; not proof the true account owner typed them)"
[ "${EVIDENCE[7]}" = "yes" ] && echo "- Exfiltrated data content, based on decoded DNS labels/tunnel structure (partial decode only, not a full data reconstruction)"
echo ""

echo "=== CANNOT CONFIRM FROM PCAP ALONE ==="
echo "- Exact password entered on the phishing page or VPN login prompt"
echo "- Whether endpoint malware executed on any host"
echo "- Whether a SIEM or monitoring alert actually fired during the incident"
echo "- Whether the user intentionally approved any login/MFA prompt"
echo "- Whether all exfiltrated data records were successfully received by the attacker"
if [ "${EVIDENCE[6]}" != "yes" ]; then
    echo "- Whether SMB-based discovery/enumeration occurred at all — not visible in this module's captures, so"
    echo "  this is reported as NOT VISIBLE rather than assumed to have happened off-camera"
fi
echo ""

echo "=== ADDITIONAL EVIDENCE NEEDED ==="
echo "- Endpoint process logs (EDR/host telemetry) — for malware execution, exact keystrokes/credential entry"
echo "- VPN authentication/gateway logs — for the true authenticated account and MFA status"
echo "- Domain controller / authentication logs — for definitive account identity on RDP and VPN sessions"
echo "- Mail gateway logs — for the original phishing email's delivery, headers and recipient list (Phase 1)"
echo "- User interview — for intent (did the user knowingly click/approve, or was this fully automated)"
echo "- Server-side logs (web/file server, SIEM alert history) — for confirmation of data actually exfiltrated"
[ "${EVIDENCE[6]}" != "yes" ] && echo "- Server/endpoint logs on the target host — to determine whether SMB enumeration or file access happened outside this capture window"
echo ""

TOTAL=7
PCT=$(awk -v y="$YES_COUNT" -v t="$TOTAL" 'BEGIN{printf "%.0f", (y/t)*100}')
echo "=== PACKET VISIBILITY SCORE ==="
echo "Direct PCAP evidence exists for $YES_COUNT of $TOTAL phases."
echo "Packet visibility: ${PCT}%"
echo ""

echo "=== WHERE PACKET EVIDENCE IS STRONG ==="
echo "PCAPs are strongest at proving that communication happened: which hosts"
echo "talked to which, over what protocol, when, how often, and for how long."
echo "Behavioral patterns built from that alone — like the beaconing interval"
echo "regularity in Phase 3, or the anomalous DNS label lengths in Phase 7 — are"
echo "directly observable and require no assumption about intent."
echo ""

echo "=== WHERE PACKET EVIDENCE HAS LIMITS ==="
echo "PCAPs cannot see inside encrypted payloads (TLS application data, NLA-"
echo "encrypted RDP logons), cannot see endpoint-side state (process execution,"
echo "whether a user consciously clicked or typed something), and only cover"
echo "whatever traffic the capture window actually contains — activity before,"
echo "after, or simply not routed through the tapped link leaves no trace here"
echo "at all, which is exactly what happened with SMB discovery in this module."
echo ""

echo "KEY LESSON:"
echo "Packets show communication. They do not always show user intent,"
echo "plaintext credentials or endpoint process state. Strong investigations"
echo "separate packet facts from analytical inference, and log evidence (auth,"
echo "endpoint, server) is what closes the gap packet evidence cannot reach —"
echo "neither source alone tells the whole story."
echo "================================================================"
