#!/bin/bash
#
# 4-lateral_movement.sh
#
# MedDefense Health Systems — Wireshark Territory (Task 4: The Lateral Trail)
#
# Purpose
#   Analyzes lateral_movement.pcap for cross-subnet traffic, authentication
#   events (Kerberos, NTLM, RDP/NLA, SMB), failed/refused connections, SMB
#   enumeration, a reconstructed attacker path, a comparison against
#   expected/baseline behavior, and a MITRE ATT&CK mapping grounded in what
#   was actually observed in the packets — this task's own evidence, not
#   the Module 2 segmentation rules from an earlier version of this task.
#
#   This script uses tshark only. Wireshark's GUI is for manual, exploratory
#   investigation and is not part of this automated deliverable.
#
# Usage
#   ./4-lateral_movement.sh lateral_movement.pcap
#
# Requirements
#   - tshark (Wireshark CLI) must be installed and on PATH.
#   - awk, sort, uniq, grep (standard on Kali).
#   - python3 (used to correlate SMB2/Kerberos request-response pairs across
#     several tshark extractions into a single chronological events table,
#     and to build the JSON output. If python3 is missing, the script says
#     so and skips the correlated table instead of guessing at pairings).
#
# Reproducibility note
#   Every measurement below is produced by an explicit tshark command or
#   display filter, printed as a comment directly above the line that runs
#   it, so any analyst can re-run the exact same query by hand against the
#   same file and get the same numbers and timestamps.
#
# Honesty note
#   Several fields requested by this task (Kerberos account names, NTLM
#   usernames, RDP/NLA success or failure) are only extractable when the
#   protocol exposes them in plaintext at the packet level — RDP/NLA in
#   particular wraps its credential exchange in TLS (CredSSP), so no
#   account name or explicit success/failure is visible there short of a
#   completed, decryptable session. Where a field genuinely is not visible
#   in the packets, this script prints "not visible in this capture"
#   instead of guessing — this matches the task's own repeated "if visible"
#   wording.
#
set -uo pipefail
# Deliberately not using -e: several tshark/grep calls below are expected to
# return no matches, which makes grep/wc exit non-zero on some systems.
# Every value is checked and defaulted instead of letting the script die.

PCAP="${1:-}"
OUTFILE="lateral_movement_findings.json"

# Known hosts from this investigation (4x00 + earlier Wireshark Territory
# tasks), used only for human-readable labels in the output, never to
# assume a finding before checking the packets.
declare -A KNOWN_HOSTS=(
    ["10.10.2.15"]="WS-NURSE-04"
    ["10.10.1.10"]="billing-srv-01"
    ["10.10.1.20"]="ehr-srv-01 (assumed from 4x00/Task 0 context — verify)"
    ["10.10.1.60"]="NAS-01 (assumed from context — verify)"
)

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <lateral_movement.pcap>" >&2
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

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

label_host() {
    local ip="$1"
    local name="${KNOWN_HOSTS[$ip]:-}"
    if [ -n "$name" ]; then
        echo "$ip ($name)"
    else
        echo "$ip"
    fi
}

echo "\$ ./4-lateral_movement.sh $PCAP"
echo ""

# ---------------------------------------------------------------------------
# 1. Cross-subnet traffic
#    Command: tshark -r <pcap> -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
#             -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport
#    A connection is "cross-subnet" when the source and destination /24
#    prefixes differ (generic check, not hardcoded to specific subnet
#    numbers beyond the 10.10.2.x/10.10.1.x named in the task brief).
# ---------------------------------------------------------------------------

tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null \
    > "$WORKDIR/syn_events.tsv"

echo "=== CROSS-SUBNET TRAFFIC ==="
if [ "$HAVE_PYTHON3" -eq 1 ]; then
    python3 - "$WORKDIR/syn_events.tsv" <<'PYEOF'
import sys

path = sys.argv[1]
rows = []
with open(path) as f:
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 3:
            continue
        ts, src, dst = parts[0], parts[1], parts[2]
        dport = parts[3] if len(parts) > 3 else ""
        rows.append((float(ts), src, dst, dport))

def prefix24(ip):
    octs = ip.split(".")
    return ".".join(octs[:3]) if len(octs) == 4 else ip

cross = [r for r in rows if prefix24(r[1]) != prefix24(r[2])]
pairs = sorted(set((r[1], r[2]) for r in cross))

print(f"Total cross-subnet connections: {len(cross)}")
print(f"Unique source-destination pairs: {len(pairs)}")

nurse_ip = "10.10.2.15"
nurse_n = sum(1 for r in cross if r[1] == nurse_ip or r[2] == nurse_ip)
print(f"Connections involving WS-NURSE-04 ({nurse_ip}): {nurse_n}")

with open(path + ".cross", "w") as out:
    for r in sorted(cross):
        out.write(f"{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\n")
PYEOF
else
    echo "python3 not available — cross-subnet SYN pairs listed raw below instead of a summarized count:"
    awk -F'\t' '{split($2,a,"."); split($3,b,"."); if (a[1]"."a[2]"."a[3] != b[1]"."b[2]"."b[3]) print}' "$WORKDIR/syn_events.tsv"
fi
echo ""

# ---------------------------------------------------------------------------
# 2 & 3. Authentication-related events
#    Kerberos: tshark -r <pcap> -Y "kerberos" -T fields -e frame.time_epoch \
#              -e ip.src -e ip.dst -e kerberos.CNameString -e kerberos.msg_type
#    SMB2 Session Setup (request):
#              tshark -r <pcap> -Y "smb2.cmd==1 && smb2.flags.response==0" \
#              -T fields -e frame.time_epoch -e ip.src -e ip.dst \
#              -e ntlmssp.auth.username -e smb2.msg_id
#    SMB2 Session Setup (response):
#              tshark -r <pcap> -Y "smb2.cmd==1 && smb2.flags.response==1" \
#              -T fields -e frame.time_epoch -e ip.src -e ip.dst \
#              -e smb2.nt_status -e smb2.msg_id
#    RDP (connection-level only — NLA wraps credentials in TLS/CredSSP, so
#    no account name or explicit success/failure is visible at this layer):
#              tshark -r <pcap> -Y "tcp.port==3389 && tcp.flags.syn==1 && tcp.flags.ack==0" \
#              -T fields -e frame.time_epoch -e ip.src -e ip.dst
#              tshark -r <pcap> -Y "tls.handshake.type==1 && tcp.port==3389" \
#              -T fields -e frame.time_epoch   (presence = NLA/CredSSP negotiated)
# ---------------------------------------------------------------------------

tshark -r "$PCAP" -Y "kerberos" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e kerberos.CNameString -e kerberos.msg_type 2>/dev/null \
    > "$WORKDIR/kerberos.tsv"

tshark -r "$PCAP" -Y "smb2.cmd==1 && smb2.flags.response==0" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e ntlmssp.auth.username -e smb2.msg_id 2>/dev/null \
    > "$WORKDIR/smb_req.tsv"

tshark -r "$PCAP" -Y "smb2.cmd==1 && smb2.flags.response==1" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e smb2.nt_status -e smb2.msg_id 2>/dev/null \
    > "$WORKDIR/smb_resp.tsv"

tshark -r "$PCAP" -Y "tcp.port==3389 && tcp.flags.syn==1 && tcp.flags.ack==0" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst 2>/dev/null \
    > "$WORKDIR/rdp_syn.tsv"

tshark -r "$PCAP" -Y "tcp.flags.reset==1" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null \
    > "$WORKDIR/tcp_rst.tsv"

echo "=== AUTHENTICATION EVENTS ==="
if [ "$HAVE_PYTHON3" -eq 1 ]; then
    python3 - "$WORKDIR" <<'PYEOF'
import sys, os

wd = sys.argv[1]

def read_tsv(name, ncols):
    rows = []
    p = os.path.join(wd, name)
    if not os.path.exists(p):
        return rows
    with open(p) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            parts += [""] * (ncols - len(parts))
            rows.append(parts[:ncols])
    return rows

STATUS_MAP = {
    "0x00000000": "SUCCESS",
    "0xc000006d": "ACCESS DENIED (logon failure)",
    "0xc0000022": "ACCESS DENIED",
    "0xc000005e": "ACCESS DENIED (no logon servers)",
}

events = []  # (ts, src, dst, account, proto, result)

# Kerberos
KRB_MSG = {10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP", 30: "KRB-ERROR"}
for ts, src, dst, cname, msgtype in read_tsv("kerberos.tsv", 5):
    if not ts:
        continue
    try:
        mt = int(msgtype) if msgtype else None
    except ValueError:
        mt = None
    result = "KRB-ERROR (failure)" if mt == 30 else ("REQUEST/REPLY seen" if mt else "n/a")
    account = cname if cname else "not visible in this capture"
    events.append((float(ts), src, dst, account, "Kerberos", result))

# SMB2 session setup: correlate request (has account, msg_id) with
# response (has status, msg_id) on the same msg_id.
smb_req = read_tsv("smb_req.tsv", 5)
smb_resp = read_tsv("smb_resp.tsv", 5)
resp_by_id = {}
for ts, src, dst, status, msgid in smb_resp:
    if msgid:
        resp_by_id[msgid] = (float(ts), src, dst, status)

for ts, src, dst, account, msgid in smb_req:
    if not ts:
        continue
    resp = resp_by_id.get(msgid)
    if resp:
        status = resp[3]
        result = STATUS_MAP.get(status.lower(), f"status {status}" if status else "response seen, status field not visible")
    else:
        result = "no matching response found in this capture"
    account_label = account if account else "not visible in this capture"
    events.append((float(ts), src, dst, account_label, "SMB", result))

# RDP: connection-level only, no account/result visible at this layer
for ts, src, dst in read_tsv("rdp_syn.tsv", 3):
    if not ts:
        continue
    events.append((float(ts), src, dst, "not visible in this capture", "RDP/NLA",
                    "connection attempted (success/failure not visible — NLA credentials are TLS-wrapped)"))

# TCP RST: refused/reset connections
for ts, src, dst, dport in read_tsv("tcp_rst.tsv", 4):
    if not ts:
        continue
    events.append((float(ts), src, dst, "n/a", f"TCP:{dport}" if dport else "TCP", "TCP RST / refused"))

events.sort(key=lambda e: e[0])

def fmt_time(t):
    import time
    return time.strftime("%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}"

if not events:
    print("No authentication-related events (Kerberos, SMB session setup, RDP connection, TCP RST) found in this capture.")
else:
    print(f"{'Timestamp':<20}| {'Source':<12}| {'Dest':<12}| {'Account':<20}| {'Proto':<10}| Result")
    print("-" * 20 + "|" + "-" * 13 + "|" + "-" * 13 + "|" + "-" * 21 + "|" + "-" * 11 + "|" + "-" * 10)
    for ts, src, dst, account, proto, result in events:
        print(f"{fmt_time(ts):<20}| {src:<12}| {dst:<12}| {account:<20}| {proto:<10}| {result}")

with open(os.path.join(wd, "events.tsv"), "w") as out:
    for e in events:
        out.write("\t".join(str(x) for x in e) + "\n")
PYEOF
else
    echo "python3 not available — correlated auth events table cannot be built."
    echo "Raw extractions are in the intermediate TSV files this run would have used:"
    echo "kerberos.tsv, smb_req.tsv, smb_resp.tsv, rdp_syn.tsv, tcp_rst.tsv"
fi
echo ""

# ---------------------------------------------------------------------------
# 6. SMB enumeration: tree connects (shares) and directory listings
#    Command: tshark -r <pcap> -Y "smb2.cmd==3 && smb2.flags.response==0" \
#             -T fields -e frame.time_epoch -e ip.src -e ip.dst -e smb2.tree
#    Command: tshark -r <pcap> -Y "smb2.cmd==14 && smb2.flags.response==1" \
#             -T fields -e frame.time_epoch -e ip.src -e ip.dst -e smb2.filename
# ---------------------------------------------------------------------------

echo "=== SMB ENUMERATION ==="
TREE_CONNECTS=$(tshark -r "$PCAP" -Y "smb2.cmd==3 && smb2.flags.response==0" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e smb2.tree 2>/dev/null)
if [ -n "$TREE_CONNECTS" ]; then
    echo "Shares accessed (tree connect requests):"
    echo "$TREE_CONNECTS" | awk -F'\t' '{printf "  %s  %s -> %s  %s\n", $1, $2, $3, ($4=="" ? "(share path not visible)" : $4)}'
else
    echo "No SMB tree connect requests found in this capture."
fi

QUERYDIR=$(tshark -r "$PCAP" -Y "smb2.cmd==14 && smb2.flags.response==1" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst -e smb2.filename 2>/dev/null)
if [ -n "$QUERYDIR" ]; then
    QUERYDIR_N=$(echo "$QUERYDIR" | grep -c '^' || true)
    echo "Directory listing (Query Directory) responses observed: $QUERYDIR_N"
    echo "$QUERYDIR" | awk -F'\t' '$4!="" {print "  "$1"  "$2" -> "$3"  entry: "$4}' | head -20
    echo "  (Note: entry counts reflect one filename field per response frame as parsed by tshark;"
    echo "   a single response can carry multiple directory entries that this simple field extraction"
    echo "   may undercount — treat this as a lower bound, not an exact file count.)"
else
    echo "No SMB Query Directory (listing) activity found in this capture."
fi
echo ""

# ---------------------------------------------------------------------------
# 5. Failed connections: TCP RST and access-denied patterns (summarized;
#    also feeds the AUTHENTICATION EVENTS table above)
# ---------------------------------------------------------------------------

echo "=== FAILED / REFUSED CONNECTIONS ==="
RST_LINES=$(cat "$WORKDIR/tcp_rst.tsv" 2>/dev/null)
if [ -n "$RST_LINES" ]; then
    RST_N=$(echo "$RST_LINES" | grep -c '^' || true)
    echo "TCP RST packets observed: $RST_N"
    echo "$RST_LINES" | awk -F'\t' '{printf "  %s  %s -> %s:%s  RST\n", $1, $2, $3, $4}' | head -20
    echo ""
    echo "[*] Interpretation from packet evidence only: a TCP RST sent in response to a"
    echo "    connection attempt (rather than a completed handshake followed by protocol"
    echo "    activity) means the destination actively refused the connection at the TCP"
    echo "    layer — before any application-level authentication could occur. This is"
    echo "    distinct from an application-level 'access denied' (e.g. SMB STATUS_ACCESS_DENIED),"
    echo "    which means the TCP connection succeeded but credentials/permissions were rejected."
else
    echo "No TCP RST packets found in this capture."
fi
echo ""

# ---------------------------------------------------------------------------
# 4. Attack path reconstruction + 7. baseline comparison + 8. MITRE mapping
#    Built from the events already extracted above, in chronological order.
# ---------------------------------------------------------------------------

echo "=== ATTACK PATH RECONSTRUCTION ==="
if [ "$HAVE_PYTHON3" -eq 1 ] && [ -f "$WORKDIR/events.tsv" ]; then
    python3 - "$WORKDIR/events.tsv" "$WORKDIR/syn_events.tsv.cross" <<'PYEOF'
import sys, os

events_path, cross_path = sys.argv[1], sys.argv[2]

events = []
if os.path.exists(events_path):
    with open(events_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            ts, src, dst, account, proto, result = parts[:6]
            events.append((float(ts), src, dst, account, proto, result))

cross = []
if os.path.exists(cross_path):
    with open(cross_path) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            ts, src, dst = parts[0], parts[1], parts[2]
            cross.append((float(ts), src, dst))

events.sort(key=lambda e: e[0])
cross.sort(key=lambda e: e[0])

if not cross:
    print("No cross-subnet connections found — no attacker path to reconstruct from this capture.")
else:
    start_src = cross[0][1]
    first_dst = cross[0][2]
    print(f"Starting system: {start_src}")
    print(f"First internal destination reached: {first_dst}")

    dests_reached = []
    seen = set()
    for ts, src, dst, account, proto, result in events:
        if "SUCCESS" in result and dst not in seen:
            dests_reached.append((dst, proto, ts))
            seen.add(dst)

    if dests_reached:
        print("Subsequent systems successfully accessed (in order):")
        for dst, proto, ts in dests_reached:
            print(f"  {dst} via {proto}")
    else:
        print("No successful (SUCCESS-status) subsequent system access found in the correlated events.")

    denied = sorted(set((dst,) for ts, src, dst, account, proto, result in events if "ACCESS DENIED" in result))
    if denied:
        print("Systems that denied access:")
        for (dst,) in denied:
            print(f"  {dst}")
PYEOF
    # RST-based refused destinations, listed separately (kept out of the
    # python block above to avoid re-parsing the same file twice).
    # IMPORTANT: the system that REFUSED the connection is the one that SENT
    # the RST packet, i.e. its ip.src (column 2 in tcp_rst.tsv) — not the
    # ip.dst (column 3), which is the host whose connection attempt was
    # rejected. Printing column 3 here would name the wrong side.
    if [ -s "$WORKDIR/tcp_rst.tsv" ]; then
        echo "Systems that returned TCP RST / refused the connection:"
        awk -F'\t' '{print "  "$2}' "$WORKDIR/tcp_rst.tsv" | sort -u
    fi
else
    echo "python3 not available, or no correlated events were produced — attack path reconstruction skipped."
fi
echo ""

echo "=== ACCESS EFFECTIVENESS ==="
if [ -f "$WORKDIR/events.tsv" ]; then
    SUCCESS_LINES=$(awk -F'\t' '$6 ~ /SUCCESS/' "$WORKDIR/events.tsv")
    DENIED_LINES=$(awk -F'\t' '$6 ~ /ACCESS DENIED/' "$WORKDIR/events.tsv")
    echo "Succeeded:"
    if [ -n "$SUCCESS_LINES" ]; then
        echo "$SUCCESS_LINES" | awk -F'\t' '{print "  "$2" -> "$3" via "$5}' | sort -u
    else
        echo "  (none found in this capture)"
    fi
    echo "Denied or refused:"
    if [ -n "$DENIED_LINES" ]; then
        echo "$DENIED_LINES" | awk -F'\t' '{print "  "$2" -> "$3" via "$5}' | sort -u
    else
        echo "  (none found in this capture)"
    fi
else
    echo "(events table not available — see AUTHENTICATION EVENTS section above)"
fi
echo ""

echo "=== BASELINE COMPARISON ==="
echo "This script does not assume prior segmentation rules (per this task's"
echo "instructions) and instead compares against Task 0's baseline_clinical.json"
echo "when available next to this script."
BASELINE_FILE="$(dirname "$PCAP")/baseline_clinical.json"
[ ! -f "$BASELINE_FILE" ] && BASELINE_FILE="./baseline_clinical.json"
if [ -f "$BASELINE_FILE" ]; then
    echo "Baseline file found: $BASELINE_FILE"
    echo "Does WS-NURSE-04 (10.10.2.15) normally appear as an RDP source to billing-srv-01 in the baseline? Check baseline_clinical.json's known-good service list manually — this script does not yet cross-reference per-host RDP behavior automatically."
else
    echo "No baseline_clinical.json found next to this script. Cannot make an automated"
    echo "yes/no comparison here — re-run 0-baseline_analysis.sh first, or note manually"
    echo "in your report whether this RDP/SMB pattern appeared in the 30-minute baseline."
fi
echo ""

echo "=== MITRE ATT&CK MAPPING ==="
echo "Techniques below are reported ONLY where this run found corresponding evidence:"
ANY_ACCOUNT=$(awk -F'\t' '$4!="" && $4!="not visible in this capture" && $4!="n/a"' "$WORKDIR/events.tsv" 2>/dev/null | head -1)
[ -n "$ANY_ACCOUNT" ] && echo "  T1078.002  Valid Accounts: Domain Accounts — account name observed in at least one auth event" \
    || echo "  T1078.002  Valid Accounts: Domain Accounts — NOT confirmed (no account name was visible at packet level)"
[ -s "$WORKDIR/rdp_syn.tsv" ] && echo "  T1021.001  Remote Desktop Protocol — RDP connection(s) observed" \
    || echo "  T1021.001  Remote Desktop Protocol — NOT observed in this capture"
[ -s "$WORKDIR/smb_req.tsv" ] && echo "  T1021.002  SMB/Windows Admin Shares — SMB session setup activity observed" \
    || echo "  T1021.002  SMB/Windows Admin Shares — NOT observed in this capture"
[ -n "$TREE_CONNECTS" ] && echo "  T1135      Network Share Discovery — SMB tree connect (share enumeration) observed" \
    || echo "  T1135      Network Share Discovery — NOT observed in this capture"
[ -n "$QUERYDIR" ] && echo "  T1083      File and Directory Discovery — SMB directory listing observed" \
    || echo "  T1083      File and Directory Discovery — NOT observed in this capture"
echo ""

# ---------------------------------------------------------------------------
# Persist findings to JSON
# ---------------------------------------------------------------------------

if [ "$HAVE_PYTHON3" -eq 1 ]; then
    python3 - "$WORKDIR" "$PCAP" "$OUTFILE" <<'PYEOF'
import sys, os, json

wd, pcap, outfile = sys.argv[1], sys.argv[2], sys.argv[3]

def read_tsv(name, ncols):
    rows = []
    p = os.path.join(wd, name)
    if not os.path.exists(p):
        return rows
    with open(p) as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            parts += [""] * (ncols - len(parts))
            rows.append(parts[:ncols])
    return rows

events = read_tsv("events.tsv", 6)
cross = read_tsv("syn_events.tsv.cross", 4)

data = {
    "source_pcap": pcap,
    "generated_by": "4-lateral_movement.sh",
    "cross_subnet_connections": len(cross),
    "unique_cross_subnet_pairs": len(set((r[1], r[2]) for r in cross)) if cross else 0,
    "auth_events_count": len(events),
    "success_events": [e for e in events if "SUCCESS" in e[5]],
    "denied_events": [e for e in events if "ACCESS DENIED" in e[5]],
    "notes": "Fields not exposed in plaintext at the packet level (e.g. RDP/NLA account names, which are TLS-wrapped) are reported as 'not visible in this capture' rather than guessed. MITRE techniques are reported only where this run found corresponding packet evidence."
}
with open(outfile, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
print(f"FINDINGS SAVED: {outfile}")
PYEOF
else
    echo "{\"source_pcap\": \"$PCAP\", \"generated_by\": \"4-lateral_movement.sh\", \"note\": \"python3 unavailable — minimal JSON only\"}" > "$OUTFILE"
    echo "FINDINGS SAVED: $OUTFILE (minimal — python3 was unavailable)"
fi
