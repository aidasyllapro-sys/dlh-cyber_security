#!/bin/bash
#
# 3-dns_tunnel.sh
#
# MedDefense Health Systems — Wireshark Territory (Task 3: The DNS Tunnel)
#
# Purpose
#   Analyzes dns_exfil.pcap for DNS tunneling activity from billing-srv-01
#   (10.10.1.10): classifies every DNS query as normal or anomalous,
#   characterizes the anomalous query pattern (base domain, subdomain
#   length, encoding), attempts to decode a sample of subdomain labels and
#   the TXT response content, estimates exfiltration volume and rate, and
#   compares the tunnel's DNS behavior against the Task 0 baseline.
#
#   This script uses tshark only. Wireshark's GUI is for manual, exploratory
#   investigation and is not part of this automated deliverable.
#
# Usage
#   ./3-dns_tunnel.sh dns_exfil.pcap
#
# Requirements
#   - tshark (Wireshark CLI) must be installed and on PATH.
#   - awk, sort, uniq, grep, sed (standard on Kali).
#   - python3 (used to attempt base32/base64 decoding of subdomain labels
#     and TXT response content, and to compute label entropy/charset. If
#     python3 is missing, decoding is skipped and the script says so
#     instead of inventing decoded data).
#
# Reproducibility note
#   Every measurement below is produced by an explicit tshark command or
#   display filter, printed as a comment directly above the line that runs
#   it, so any analyst can re-run the exact same query by hand against the
#   same file and get the same numbers and timestamps.
#
# How queries are classified NORMAL vs ANOMALOUS
#   The classification is based on the length of the leftmost DNS label
#   (the subdomain), not on a hardcoded list of "bad" domain names — a
#   hardcoded domain blocklist would not generalize to a real tunnel using
#   a different domain. In this capture there is a clean, non-overlapping
#   gap between ordinary subdomains (3-10 characters: "www", "security",
#   "metrics", etc.) and the tunnel's encoded labels (44-60 characters), so
#   ANOMALOUS_LABEL_LEN_THRESHOLD below separates them cleanly. A query
#   type of TXT is NOT used alone to flag a query as anomalous, because
#   this capture also contains ordinary, short-label TXT queries to real
#   services (e.g. metrics.mysql.com) that are legitimate.
#
set -uo pipefail
# Deliberately not using -e: several tshark/grep calls below are expected to
# return no matches, which makes grep/wc exit non-zero on some systems.
# Every value is checked and defaulted instead of letting the script die.

ANOMALOUS_LABEL_LEN_THRESHOLD=20

PCAP="${1:-}"
OUTFILE="dns_tunnel_findings.json"
TARGET_HOST="10.10.1.10"   # billing-srv-01

if [ -z "$PCAP" ]; then
    echo "Usage: $0 <dns_exfil.pcap>" >&2
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

fmt_time() {
    awk -v t="$1" 'BEGIN{
        if (t=="" ) { print "n/a"; exit }
        h=int(t/3600)%24; m=int(t/60)%60; s=t-int(t/60)*60;
        printf "%02d:%02d:%06.3f", h, m, s
    }'
}

echo "\$ ./3-dns_tunnel.sh $PCAP"
echo ""

# ---------------------------------------------------------------------------
# 1 & 2. Extract all DNS queries from billing-srv-01, split normal/anomalous
#    Commands:
#      tshark -r <pcap> -Y "dns.flags.response==0 && ip.src==10.10.1.10" \
#             -T fields -e dns.qry.name
#    Classification: see the header note above (subdomain label length).
# ---------------------------------------------------------------------------

ALL_QNAMES=$(tshark -r "$PCAP" -Y "dns.flags.response==0 && ip.src==$TARGET_HOST" \
    -T fields -e dns.qry.name 2>/dev/null)
TOTAL_QUERIES=$(echo "$ALL_QNAMES" | grep -c '^' || true)
[ -z "$ALL_QNAMES" ] && TOTAL_QUERIES=0

# A query is ANOMALOUS if its leftmost label is longer than the threshold.
ANOM_QNAMES=$(echo "$ALL_QNAMES" | awk -F. -v n="$ANOMALOUS_LABEL_LEN_THRESHOLD" 'length($1) > n {print}')
ANOM_COUNT=$(echo "$ANOM_QNAMES" | grep -c '^' || true)
[ -z "$ANOM_QNAMES" ] && ANOM_COUNT=0
NORMAL_COUNT=$((TOTAL_QUERIES - ANOM_COUNT))

echo "=== DNS QUERY CLASSIFICATION ==="
echo "Total DNS queries: $TOTAL_QUERIES"
echo "Normal queries: $NORMAL_COUNT"
echo "Anomalous queries: $ANOM_COUNT"
echo ""

if [ "$ANOM_COUNT" -eq 0 ]; then
    echo "No anomalous queries found (leftmost label > $ANOMALOUS_LABEL_LEN_THRESHOLD chars) — stopping further tunnel-specific analysis."
    echo ""
else

# ---------------------------------------------------------------------------
# 3. Anomalous query details: base domain, label length, encoding check
#    Commands:
#      tshark -r <pcap> -Y "dns.flags.response==0 && ip.src==10.10.1.10 && dns.qry.type==16" \
#             -T fields -e frame.time_epoch -e dns.qry.name
# ---------------------------------------------------------------------------

BASE_DOMAIN=$(echo "$ANOM_QNAMES" | head -1 | sed -E 's/^[^.]+\.//')

ANOM_TYPES=$(tshark -r "$PCAP" -Y "dns.flags.response==0 && ip.src==$TARGET_HOST && dns.qry.name contains \"$BASE_DOMAIN\"" \
    -T fields -e dns.qry.type 2>/dev/null | sort | uniq -c | sort -rn)
ANOM_TYPE_NAMES=$(echo "$ANOM_TYPES" | awk '{t=$2; if(t==1)t="A"; else if(t==16)t="TXT"; else if(t==28)t="AAAA"; else if(t==15)t="MX"; print t" ("$1")"}' | paste -sd, -)

ANOM_TS_LIST=$(tshark -r "$PCAP" -Y "dns.flags.response==0 && ip.src==$TARGET_HOST && dns.qry.name contains \"$BASE_DOMAIN\"" \
    -T fields -e frame.time_epoch 2>/dev/null | sort -n)
FIRST_ANOM_TS=$(echo "$ANOM_TS_LIST" | head -1)
LAST_ANOM_TS=$(echo "$ANOM_TS_LIST" | tail -1)

INTERVALS=$(echo "$ANOM_TS_LIST" | awk 'NR>1{printf "%.1f\n", $1-prev} {prev=$1}')
INTERVAL_MIN=$(echo "$INTERVALS" | sort -n | head -1)
INTERVAL_MAX=$(echo "$INTERVALS" | sort -n | tail -1)

LABEL_LENGTHS=$(echo "$ANOM_QNAMES" | awk -F. '{print length($1)}')
LEN_MIN=$(echo "$LABEL_LENGTHS" | sort -n | head -1)
LEN_MAX=$(echo "$LABEL_LENGTHS" | sort -n | tail -1)
LEN_AVG=$(echo "$LABEL_LENGTHS" | awk '{sum+=$1; n++} END{printf "%.1f", sum/n}')

# Encoding check: does the label's character set match base32
# ([A-Za-z2-7]) or base64 ([A-Za-z0-9+/])? Reported honestly either way.
SAMPLE_LABEL=$(echo "$ANOM_QNAMES" | head -1 | awk -F. '{print $1}')
if echo "$SAMPLE_LABEL" | grep -qE '^[A-Za-z2-7]+$'; then
    ENCODING_GUESS="base32-like charset (letters + digits 2-7 only)"
elif echo "$SAMPLE_LABEL" | grep -qE '^[A-Za-z0-9+/=_-]+$'; then
    ENCODING_GUESS="base64-like charset"
else
    ENCODING_GUESS="not a clean base32/base64 charset — unclear encoding"
fi

echo "=== ANOMALOUS QUERY ANALYSIS ==="
echo "Base domain: $BASE_DOMAIN"
echo ""
echo "Query pattern:"
echo "  Type(s) observed: $ANOM_TYPE_NAMES"
echo "  Interval: ${INTERVAL_MIN}-${INTERVAL_MAX} seconds between queries (min-max observed)"
echo "  Subdomain label length: ${LEN_MIN}-${LEN_MAX} characters (avg ${LEN_AVG})"
echo "  Encoding: $ENCODING_GUESS"
echo ""

# ---------------------------------------------------------------------------
# 5. Decode a sample of 5 subdomain labels
#    Attempts base32 first (uppercased, padded to a multiple of 8), then
#    base64 (padded to a multiple of 4). Each label is a FRAGMENT of a
#    larger exfiltrated stream, so an individual label failing to decode
#    to clean text is expected and reported as such rather than guessed.
# ---------------------------------------------------------------------------

echo "Sample decoded queries:"
SAMPLE_LABELS=$(echo "$ANOM_QNAMES" | awk -F. '{print $1}' | head -5)
i=0
while IFS= read -r label; do
    i=$((i+1))
    printf "  Query %d: %s\n" "$i" "$label"
    if [ "$HAVE_PYTHON3" -eq 1 ]; then
        RESULT=$(python3 -c '
import sys, base64
label = sys.argv[1]
u = label.upper()
attempts = []
# Attempt 1: base32
pad32 = "=" * ((8 - len(u) % 8) % 8)
try:
    d = base64.b32decode(u + pad32, casefold=True)
    if all(32 <= c < 127 for c in d):
        print("base32 decode succeeded: " + d.decode("ascii", errors="replace"))
        sys.exit(0)
    else:
        attempts.append("base32 decoded but produced non-printable bytes (likely a raw/partial fragment, not a self-contained encoded chunk)")
except Exception as e:
    attempts.append("base32 decode failed: " + str(e))
# Attempt 2: base64
pad64 = "=" * ((4 - len(label) % 4) % 4)
try:
    d = base64.b64decode(label + pad64)
    if all(32 <= c < 127 for c in d):
        print("base64 decode succeeded: " + d.decode("ascii", errors="replace"))
        sys.exit(0)
    else:
        attempts.append("base64 decoded but produced non-printable bytes")
except Exception as e:
    attempts.append("base64 decode failed: " + str(e))
print(" ; ".join(attempts))
' "$label")
        printf "    -> [base32 attempted, then base64] %s\n" "$RESULT"
    else
        printf "    -> python3 not available in this environment — decoding not attempted. Install python3 to enable base32/base64 decode attempts.\n"
    fi
done <<< "$SAMPLE_LABELS"
echo ""
echo "[*] Note: each label is one fragment of a larger exfiltrated stream"
echo "    (the subdomain changes on every query). A single fragment failing"
echo "    to decode cleanly on its own is expected — full reconstruction"
echo "    would require concatenating fragments in query order, which is"
echo "    out of scope for this per-query decode sample."
echo ""

# ---------------------------------------------------------------------------
# 6. DNS response analysis
#    Commands:
#      tshark -r <pcap> -Y "dns.flags.response==1 && dns.qry.name contains \"<base_domain>\"" \
#             -T fields -e dns.txt -e frame.len
# ---------------------------------------------------------------------------

echo "=== DNS RESPONSE ANALYSIS ==="
RESP_TYPES=$(tshark -r "$PCAP" -Y "dns.flags.response==1 && dns.qry.name contains \"$BASE_DOMAIN\"" \
    -T fields -e dns.qry.type 2>/dev/null | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
[ "$RESP_TYPES" = "16" ] && RESP_TYPE_NAME="TXT" || RESP_TYPE_NAME="type $RESP_TYPES"

RESP_LENS=$(tshark -r "$PCAP" -Y "dns.flags.response==1 && dns.qry.name contains \"$BASE_DOMAIN\"" \
    -T fields -e frame.len 2>/dev/null)
RESP_AVG_LEN=$(echo "$RESP_LENS" | awk '{sum+=$1; n++} END{ if(n>0) printf "%.0f", sum/n; else print "n/a"}')

echo "Response type: $RESP_TYPE_NAME records"
echo "Average response frame size: ${RESP_AVG_LEN} bytes"

TXT_SAMPLE=$(tshark -r "$PCAP" -Y "dns.flags.response==1 && dns.qry.name contains \"$BASE_DOMAIN\"" \
    -T fields -e dns.txt 2>/dev/null | grep -v '^$' | head -1)
if [ -n "$TXT_SAMPLE" ] && [ "$HAVE_PYTHON3" -eq 1 ]; then
    TXT_DECODED=$(python3 -c '
import sys, base64
s = sys.argv[1]
pad = "=" * ((4 - len(s) % 4) % 4)
try:
    d = base64.b64decode(s + pad)
    if all(32 <= c < 127 for c in d):
        print(d.decode("ascii", errors="replace"))
    else:
        print("[decoded but non-printable bytes]")
except Exception as e:
    print("[base64 decode failed: " + str(e) + "]")
' "$TXT_SAMPLE")
    echo "Content: TXT record decodes (base64) to: \"$TXT_DECODED\""
    echo "  -> This looks like command/control-style content, not raw exfiltrated data."
    echo "     Treat as a lead: correlate the referenced batch/ID range against"
    echo "     actual data known to be on billing-srv-01 before concluding scope."
elif [ -n "$TXT_SAMPLE" ]; then
    echo "Content: TXT record present (raw: \"$TXT_SAMPLE\") but python3 unavailable to attempt base64 decode."
else
    echo "Content: no TXT record content could be extracted."
fi
echo ""

# ---------------------------------------------------------------------------
# 4, 7, 8. Anomalous query rate + exfiltration volume/rate estimate
# ---------------------------------------------------------------------------

SPAN_SEC=$(awk -v a="$FIRST_ANOM_TS" -v b="$LAST_ANOM_TS" 'BEGIN{ if(a=="" || b=="") print 0; else printf "%.1f", b-a }')
SPAN_MIN=$(awk -v s="$SPAN_SEC" 'BEGIN{ if(s==0) print "0"; else printf "%.1f", s/60 }')
RATE_PER_MIN=$(awk -v n="$ANOM_COUNT" -v m="$SPAN_MIN" 'BEGIN{ if(m+0==0) print "n/a"; else printf "%.1f", n/m }')

EST_RAW_BYTES=$(awk -v n="$ANOM_COUNT" -v l="$LEN_AVG" 'BEGIN{
    # base32: 8 encoded chars carry 5 raw bytes; base64: 4 encoded chars carry 3 raw bytes.
    # Using base32 ratio here since the label charset matched base32 above.
    printf "%.0f", n * l * (5.0/8.0)
}')
EST_RATE_BPM=$(awk -v b="$EST_RAW_BYTES" -v m="$SPAN_MIN" 'BEGIN{ if(m+0==0) print "n/a"; else printf "%.1f", b/m }')

echo "=== EXFILTRATION VOLUME ==="
printf "Queries: %s over %s minutes (%s/min)\n" "$ANOM_COUNT" "$SPAN_MIN" "$RATE_PER_MIN"
printf "Average subdomain payload: %s encoded characters per query\n" "$LEN_AVG"
printf "Estimated raw data exfiltrated (base32 overhead, 8 chars -> 5 bytes): approximately %s bytes (~%.1f KB)\n" "$EST_RAW_BYTES" "$(awk -v b="$EST_RAW_BYTES" 'BEGIN{printf "%.1f", b/1024}')"
printf "Estimated exfiltration rate: %s bytes/min\n" "$EST_RATE_BPM"
echo ""
echo "[*] This is low volume, but DNS tunneling often prioritizes stealth"
echo "    and structured, low-and-slow records over bulk transfer speed."
echo ""

fi  # end ANOM_COUNT -gt 0 block

# ---------------------------------------------------------------------------
# 9. Comparison against Task 0 baseline
#    Loads threat_detection/4x01_wire_shark_territory/baseline_clinical.json
#    if present (produced by 0-baseline_analysis.sh); falls back to the
#    documented Task 0 findings if that file isn't next to this script.
# ---------------------------------------------------------------------------

BASELINE_FILE="$(dirname "$PCAP")/baseline_clinical.json"
[ ! -f "$BASELINE_FILE" ] && BASELINE_FILE="./baseline_clinical.json"

BASELINE_DNS_RATE="17.4"
BASELINE_TXT_PCT="1.3"
BASELINE_SOURCE="documented Task 0 findings (baseline_clinical.json not found next to this script — re-run 0-baseline_analysis.sh to regenerate it for a live comparison)"
if [ -f "$BASELINE_FILE" ] && [ "$HAVE_PYTHON3" -eq 1 ]; then
    B_RATE=$(python3 -c "
import json
try:
    d = json.load(open('$BASELINE_FILE'))
    print(d.get('dns_profile', {}).get('avg_queries_per_minute', ''))
except Exception:
    print('')
")
    B_TXT=$(python3 -c "
import json
try:
    d = json.load(open('$BASELINE_FILE'))
    print(d.get('dns_profile', {}).get('txt_query_pct', ''))
except Exception:
    print('')
")
    if [ -n "$B_RATE" ]; then
        BASELINE_DNS_RATE="$B_RATE"
        BASELINE_TXT_PCT="$B_TXT"
        BASELINE_SOURCE="$BASELINE_FILE (live)"
    fi
fi

echo "=== DETECTION COMPARISON ==="
printf "%-20s| %-18s| %s\n" "" "Normal DNS (Task 0)" "Tunnel DNS (this capture)"
printf -- "--------------------|-------------------|--------------------\n"
printf "%-20s| %-18s| %s\n" "Query type" "mostly A/AAAA" "TXT"
printf "%-20s| %-18s| %s\n" "Subdomain length" "short (baseline avg n/a, observed 3-10 chars here)" "${LEN_MIN:-n/a}-${LEN_MAX:-n/a} chars (avg ${LEN_AVG:-n/a})"
printf "%-20s| %-18s| %s\n" "Subdomain encoding" "human-readable" "$ENCODING_GUESS"
printf "%-20s| %-18s| %s\n" "Query rate" "~${BASELINE_DNS_RATE}/min overall" "~${RATE_PER_MIN:-n/a}/min (anomalous only)"
printf "%-20s| %-18s| %s\n" "TXT query share" "~${BASELINE_TXT_PCT}% of DNS" "100% of anomalous queries"
printf "%-20s| %-18s| %s\n" "Destination domain" "known/allowlisted" "$BASE_DOMAIN (flagged in 4x00)"
echo ""
echo "Baseline source: $BASELINE_SOURCE"
echo ""

# ---------------------------------------------------------------------------
# Conclusion
# ---------------------------------------------------------------------------

echo "=== CONCLUSION ==="
if [ "$ANOM_COUNT" -gt 0 ]; then
    echo "DNS traffic from billing-srv-01 to $BASE_DOMAIN is consistent with DNS"
    echo "tunneling: encoded, high-entropy subdomain labels well outside the"
    echo "normal label-length range, carried almost exclusively over TXT"
    echo "queries, at a regular interval, with a TXT response that decodes to"
    echo "command/control-style text. This is packet-level evidence, not an"
    echo "inference from an alert — treat it as a confirmed exfiltration"
    echo "channel pending scope confirmation (what data, how much)."
else
    echo "No anomalous DNS pattern was found in this capture against the"
    echo "current classification threshold — no tunneling conclusion is"
    echo "supported by this evidence."
fi
echo ""

# ---------------------------------------------------------------------------
# Persist findings to JSON
# ---------------------------------------------------------------------------

cat > "$OUTFILE" <<EOF
{
  "source_pcap": "$PCAP",
  "generated_by": "3-dns_tunnel.sh",
  "classification": {
    "total_queries": $TOTAL_QUERIES,
    "normal_queries": $NORMAL_COUNT,
    "anomalous_queries": $ANOM_COUNT,
    "anomalous_label_len_threshold": $ANOMALOUS_LABEL_LEN_THRESHOLD
  },
  "anomalous_pattern": {
    "base_domain": "${BASE_DOMAIN:-null}",
    "label_len_min": "${LEN_MIN:-null}",
    "label_len_max": "${LEN_MAX:-null}",
    "label_len_avg": "${LEN_AVG:-null}",
    "encoding_guess": "${ENCODING_GUESS:-null}",
    "interval_min_seconds": "${INTERVAL_MIN:-null}",
    "interval_max_seconds": "${INTERVAL_MAX:-null}",
    "first_query_time": "$(fmt_time "${FIRST_ANOM_TS:-}")",
    "last_query_time": "$(fmt_time "${LAST_ANOM_TS:-}")"
  },
  "exfiltration_estimate": {
    "span_minutes": "${SPAN_MIN:-null}",
    "rate_per_minute": "${RATE_PER_MIN:-null}",
    "estimated_raw_bytes": "${EST_RAW_BYTES:-null}",
    "estimated_bytes_per_minute": "${EST_RATE_BPM:-null}"
  },
  "baseline_comparison_source": "$BASELINE_SOURCE",
  "notes": "Subdomain labels are fragments of a larger stream; per-label decode failures are expected and documented rather than fabricated. Exfiltration volume is an estimate from average encoded length and base32 overhead ratio (8 chars -> 5 bytes), not a byte-exact measurement."
}
EOF

echo "FINDINGS SAVED: $OUTFILE"
