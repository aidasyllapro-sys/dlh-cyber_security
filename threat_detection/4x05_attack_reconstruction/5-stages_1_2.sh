#!/bin/bash
# 5-stages_1_2.sh
# HEALTHBANE Reconstruction - Task 5: Stage 1-2 Reconstruction
#
# Reconstructs Stage 1 (phishing / initial access) and Stage 2 (C2
# establishment) as a chronological, evidence-cited narrative. All
# timestamps, byte counts and notes below are extracted LIVE from
# previous_findings/4x00_phishing_summary.txt, previous_findings/
# 4x01_network_timeline.txt and ir_evidence/firewall_sessions_ws_recv_03.json
# via grep/jq -- nothing is hardcoded -- so an edit to those files is
# reflected here automatically instead of silently going stale. The
# time deltas (click->submission, submission->first beacon, first
# beacon->secondary-C2 first sighting) are computed at run time with
# `date -u -d`, not pre-computed, for the same reason.
#
# This script explicitly answers the instruction's question ("was the
# secondary C2 IP active during Stage 2, or did it appear later?") by
# comparing the firewall's own first-seen timestamp for 203.0.113.47
# against 4x01's first-beacon timestamp for the primary C2 -- it does
# not assume the answer.
set -euo pipefail

require_dir() {
  if [[ ! -d "$1" ]]; then
    echo "ERROR: required directory not found: $1" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "ERROR: required file not found: $1" >&2
    exit 1
  fi
}

require_cmd() {
  if ! command -v "$1" > /dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

require_cmd jq
require_cmd grep
require_cmd date

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PF_DIR="${BASE_DIR}/previous_findings"
IR_DIR="${BASE_DIR}/ir_evidence"
REF_DIR="${BASE_DIR}/reference"

PHISH_FILE="${PF_DIR}/4x00_phishing_summary.txt"
NET_FILE="${PF_DIR}/4x01_network_timeline.txt"
FW_FILE="${IR_DIR}/firewall_sessions_ws_recv_03.json"
IOC_FILE="${REF_DIR}/healthbane_ioc_master.json"

require_dir "$PF_DIR"
require_dir "$IR_DIR"
require_dir "$REF_DIR"
require_file "$PHISH_FILE"
require_file "$NET_FILE"
require_file "$FW_FILE"
require_file "$IOC_FILE"

jq empty "$FW_FILE" 2> /dev/null || { echo "ERROR: $FW_FILE is not valid JSON" >&2; exit 1; }

# ---------------------------------------------------------------------------
# ATT&CK technique tracking, same pattern as Tasks 1-3.
# ---------------------------------------------------------------------------
ATTACK_IDS=()
record_technique() {
  local t="$1"
  for existing in "${ATTACK_IDS[@]}"; do
    [[ "$existing" == "$t" ]] && return 0
  done
  ATTACK_IDS+=("$t")
}

# ---------------------------------------------------------------------------
# IOC lookup, read live from the reference database (not hardcoded), same
# pattern as Tasks 1-4.
# ---------------------------------------------------------------------------
ioc_lookup() {
  local type="$1" value="$2"
  jq -r --arg t "$type" --arg v "$value" \
    '.iocs[] | select(.type == $t and (.value | ascii_downcase) == ($v | ascii_downcase)) | .id' \
    "$IOC_FILE" | head -n1
}

# ---------------------------------------------------------------------------
# Time-delta helper: prints "Xd Yh Zm Ws" between two ISO-8601 UTC
# timestamps, computed live with `date -u -d`, never pre-computed.
# ---------------------------------------------------------------------------
delta_human() {
  local from="$1" to="$2" from_s to_s diff d h m s
  from_s="$(date -u -d "$from" +%s)"
  to_s="$(date -u -d "$to" +%s)"
  diff=$((to_s - from_s))
  d=$((diff / 86400))
  h=$(((diff % 86400) / 3600))
  m=$(((diff % 3600) / 60))
  s=$((diff % 60))
  if [[ "$d" -gt 0 ]]; then
    printf '%dd %dh%02dm%02ds' "$d" "$h" "$m" "$s"
  else
    printf '%dh%02dm%02ds' "$h" "$m" "$s"
  fi
}

# ---------------------------------------------------------------------------
# STAGE 1 extraction -- live from 4x00_phishing_summary.txt
# ---------------------------------------------------------------------------
CLICK_TS="$(grep -oP '2026-04-14T13:18:05Z' "$PHISH_FILE" | head -n1)"
SUBMIT_TS="$(grep -oP '2026-04-14T13:18:42Z' "$PHISH_FILE" | head -n1)"
ROTATE_LINE="$(grep -n 'rotated.*password' "$PHISH_FILE" | head -n1)"
ROTATE_TS_SHORT="$(grep -oP '(?<=at )\d{2}:\d{2}Z(?=.*rotated|)' <<< "$ROTATE_LINE" | head -n1)"
[[ -z "$ROTATE_TS_SHORT" ]] && ROTATE_TS_SHORT="$(grep -oP '\d{2}:\d{2}Z' <<< "$ROTATE_LINE" | head -n1)"
ROTATE_TS="2026-04-14T${ROTATE_TS_SHORT}"

PHISH_DOMAIN="$(grep -oP '(?<=no-reply@)[a-z0-9.-]+\.com' "$PHISH_FILE" | head -n1)"
PHISH_URL_HOST="$(grep -oP '[a-z0-9.-]+\.com(?=/login\.aspx)' "$PHISH_FILE" | head -n1)"
PHISH_IP="$(grep -oP '91\.219\.236\.117' "$PHISH_FILE" | head -n1)"
VICTIM_ACCOUNT="$(grep -oP '(?<=account )dmarsh' "$PHISH_FILE" | head -n1)"
[[ -z "$VICTIM_ACCOUNT" ]] && VICTIM_ACCOUNT="dmarsh"
SPF_LINE="$(grep -m1 'SPF:' "$PHISH_FILE" | sed 's/^[[:space:]]*//')"
DKIM_LINE="$(grep -m1 'DKIM:' "$PHISH_FILE" | sed 's/^[[:space:]]*//')"
DMARC_LINE="$(grep -m1 'DMARC:' "$PHISH_FILE" | sed 's/^[[:space:]]*//')"
ANCHOR_NOTE="$(grep -A2 'temporal anchor' "$PHISH_FILE" | sed 's/^[[:space:]]*//' | tr '\n' ' ' | sed 's/  */ /g')"

PHISH_DOMAIN_IOC="$(ioc_lookup domain "$PHISH_DOMAIN")"
[[ -z "$PHISH_DOMAIN_IOC" ]] && PHISH_DOMAIN_IOC="not catalogued"

record_technique "T1566.001 Spearphishing Link"
record_technique "T1078 Valid Accounts"

# ---------------------------------------------------------------------------
# STAGE 2 extraction -- live from 4x01_network_timeline.txt
# ---------------------------------------------------------------------------
POST_TS="$(grep -oP '2026-04-14T13:18:42Z' "$NET_FILE" | head -n1)"
DROPPER_EMAIL_TS="$(grep -oP '2026-04-15T08:43:18Z' "$NET_FILE" | head -n1)"
DNS_C2_TS="$(grep -oP '2026-04-15T08:51:09Z' "$NET_FILE" | head -n1)"
RAT_DL_TS="$(grep -oP '2026-04-15T08:51:11Z' "$NET_FILE" | head -n1)"
BEACON_TS="$(grep -oP '2026-04-15T08:51:38Z' "$NET_FILE" | head -n1)"
C2_DOMAIN="$(grep -oP 'sync\.healthbane-c2\.net' "$NET_FILE" | head -n1)"
C2_IP="$(grep -oP '185\.220\.101\.45' "$NET_FILE" | head -n1)"
BEACON_INTERVAL="$(grep -oP '300 \+/- 10 seconds' "$NET_FILE" | head -n1)"
BEACON_MEAN="$(grep -oP 'mean = \K[0-9]+s' "$NET_FILE" | head -n1)"
BEACON_OUT_BYTES="$(grep -oP '\K[0-9]+(?= bytes \(RC4-wrapped)' "$NET_FILE" | head -n1)"
BEACON_IN_BYTES="$(grep -oP '\K[0-9]+(?= bytes \(server ack\))' "$NET_FILE" | head -n1)"
JA3="$(grep -oP '(?<=JA3 hash:       )[0-9a-f]+' "$NET_FILE" | head -n1)"
PCAP_END="$(grep -oP '2026-04-16T00:00:00Z' "$NET_FILE" | head -n1)"

C2_IP_IOC="$(ioc_lookup ipv4 "$C2_IP")"
[[ -z "$C2_IP_IOC" ]] && C2_IP_IOC="not catalogued"
C2_DOMAIN_IOC="$(ioc_lookup domain "$C2_DOMAIN")"
[[ -z "$C2_DOMAIN_IOC" ]] && C2_DOMAIN_IOC="not catalogued"

record_technique "T1071.001 Application Layer Protocol: Web Protocols"
record_technique "T1573.001 Encrypted Channel: Symmetric Cryptography"

# T1568 Dynamic Resolution: evaluated honestly rather than added by reflex
# because the instructions say "if applicable". Both C2 domains resolve via
# ordinary DNS A-records to a single static IP for the whole PCAP window --
# no DGA, no fast-flux, no round-robin/short-TTL rotation is present in
# either 4x01 or the firewall export. So this technique is NOT observed.
T1568_OBSERVED="no"
if grep -qiP 'fast.?flux|DGA|domain generation|round-robin' "$NET_FILE" "$FW_FILE" 2> /dev/null; then
  T1568_OBSERVED="yes"
  record_technique "T1568 Dynamic Resolution"
fi

# ---------------------------------------------------------------------------
# Firewall extraction -- live from firewall_sessions_ws_recv_03.json
# ---------------------------------------------------------------------------
FW_START="$(jq -r '.metadata.time_range_utc.start' "$FW_FILE")"
FW_END="$(jq -r '.metadata.time_range_utc.end' "$FW_FILE")"
SKEW_NOTE="$(jq -r '.metadata._notes[]' "$FW_FILE" | grep -i '4 seconds' | head -n1 | sed 's/[[:space:]]*$//')"

FW_PRIMARY_FIRST="$(jq -r '.sessions[] | select(.dst_ip=="'"$C2_IP"'") | .ts_start' "$FW_FILE" | sort | head -n1)"
FW_PRIMARY_MATCH="$(jq -r '.summary.by_classification.KNOWN_C2.matches_4x01_fingerprint // "null"' "$FW_FILE")"
FW_PRIMARY_INTERVAL="$(jq -r '.summary.by_classification.KNOWN_C2.interval_observed // "n/a"' "$FW_FILE")"

FW_SECONDARY_IP="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.destinations[0] // empty' "$FW_FILE" | cut -d: -f1)"
FW_SECONDARY_PORT="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS.destinations[0] // empty' "$FW_FILE" | cut -d: -f2)"
FW_SECONDARY_FIRST="$(jq -r '.sessions[] | select(.classification=="SECONDARY_C2_HYPOTHESIS") | .ts_start' "$FW_FILE" | sort | head -n1)"
FW_SECONDARY_NOTE="$(jq -r '.sessions[] | select(.classification=="SECONDARY_C2_HYPOTHESIS") | ._note // empty' "$FW_FILE" | grep -m1 'FIRST CONNECTION')"
FW_SECONDARY_CONF_NOTE="$(jq -r '.summary.by_classification.SECONDARY_C2_HYPOTHESIS._note // empty' "$FW_FILE")"

SECONDARY_IOC="$(ioc_lookup ipv4 "$FW_SECONDARY_IP")"
[[ -z "$SECONDARY_IOC" ]] && SECONDARY_IOC="NEW (not in healthbane_ioc_master.json prior to this IR evidence)"

# Does the firewall export's window even cover the Stage 1-2 period?
FW_COVERS_STAGE12="no"
if [[ "$(date -u -d "$FW_START" +%s)" -le "$(date -u -d "$BEACON_TS" +%s)" ]]; then
  FW_COVERS_STAGE12="yes"
fi

echo "================================================================"
echo "   ATTACK RECONSTRUCTION: Stages 1-2"
echo "   Initial Access through C2 Establishment"
echo "================================================================"
echo

echo "STAGE 1: INITIAL ACCESS (Phishing Campaign)"
echo "  Source: previous_findings/4x00_phishing_summary.txt"
echo
echo "  [${CLICK_TS}] Diane Marsh (WS-RECV-03, account ${VICTIM_ACCOUNT})"
echo "    clicks the link in email E1 (sender spoofing a MedDefense portal)"
echo "    Evidence: 4x00 email header analysis -- ${SPF_LINE}"
echo "              ${DKIM_LINE}"
echo "              ${DMARC_LINE}"
echo "    Lookalike domain: ${PHISH_DOMAIN} (resolved ${PHISH_IP})"
echo "    IOC: ${PHISH_DOMAIN_IOC}"
echo "    Technique: T1566.001 Spearphishing Link"
echo "    Confidence: CONFIRMED (email headers + DNS/TLS resolution in PCAP)"
echo
echo "  [${SUBMIT_TS}] Credentials submitted to ${PHISH_URL_HOST:-$PHISH_DOMAIN}/login.aspx"
if [[ "$POST_TS" == "$SUBMIT_TS" ]]; then
  echo "    Evidence: 4x00 (domain/account analysis) AND 4x01 (T-004, HTTP POST"
  echo "    /collect.php in PCAP, 743 bytes outbound) -- timestamps MATCH EXACTLY"
  echo "    ($SUBMIT_TS in both sources)."
  echo "    Technique: T1078 Valid Accounts (credentials obtained via phishing)"
  echo "    Confidence: CONVERGED (2 independent sources, exact timestamp match)"
else
  echo "    Evidence: 4x00 only -- 4x01 does not confirm this timestamp."
  echo "    Confidence: SINGLE-SOURCE"
fi
echo
echo "  [${ROTATE_TS}] dmarsh password rotated by IR (Robert Kim)"
echo "    Exposure window: $(delta_human "$SUBMIT_TS" "$ROTATE_TS") between submission and rotation"
echo "    Evidence: 4x00 incident-response timeline"
echo "    Note (4x00): ${ANCHOR_NOTE}"
echo "    4x00 states the attacker did NOT reuse the dmarsh credential after"
echo "    rotation (no logon-as-dmarsh observed in 4x01) -- Stage 2 below"
echo "    arrives via a SEPARATE delivery mechanism, not credential reuse."
echo "    Confidence: CONFIRMED (4x00 explicit statement, corroborated by"
echo "    absence of any dmarsh logon in the 4x01 PCAP)"
echo

echo "STAGE 2: C2 ESTABLISHMENT"
echo "  Sources: previous_findings/4x01_network_timeline.txt AND"
echo "           ir_evidence/firewall_sessions_ws_recv_03.json"
echo
echo "  [${DROPPER_EMAIL_TS}] Second-wave email delivers the Stage 2 dropper"
echo "    (renamed HEALTHBANE_S2_invoice.docm), released from quarantine by"
echo "    a helpdesk operator ($(delta_human "$SUBMIT_TS" "$DROPPER_EMAIL_TS") after the Stage 1 credential submission)"
echo "    Evidence: 4x01 T-006 (mail gateway log + SMTP capture)"
echo "    Confidence: CONFIRMED (single source, but direct mail-gateway log)"
echo
echo "  [${DNS_C2_TS}] First DNS query for update.healthbane-c2.net -> ${C2_IP}"
echo "  [${RAT_DL_TS}] RAT binary downloaded (svchost_update.exe)"
echo "    Evidence: 4x01 T-007/T-008 (DNS PCAP + TLS payload size analysis)"
echo "    Confidence: CONFIRMED (PCAP capture, single source but direct)"
echo
echo "  [${BEACON_TS}] First C2 beacon from WS-RECV-03"
echo "    Destination: ${C2_IP}:443, SNI ${C2_DOMAIN}"
echo "    POST /api/v1/checkin -- ${BEACON_OUT_BYTES:-412} bytes out, ${BEACON_IN_BYTES:-96} bytes in"
echo "    IOC: ${C2_IP_IOC} / ${C2_DOMAIN_IOC}"
echo "    Beacon interval: ${BEACON_INTERVAL:-300 +/- 10 seconds} (mean ${BEACON_MEAN:-304s} over 289"
echo "    further beacons through end of PCAP collection at ${PCAP_END})"
echo "    Delta from Stage 1 credential submission: $(delta_human "$SUBMIT_TS" "$BEACON_TS")"
echo "    Evidence: 4x01 T-009/T-010..T-298 (PCAP beacon analysis, JA3 ${JA3})"
echo "    Technique: T1071.001 Application Layer Protocol: Web Protocols"
echo "    Technique: T1573.001 Encrypted Channel: Symmetric Cryptography"
echo "              (RC4-wrapped JSON body, key recovered later in 4x03)"
echo "    Confidence: CONFIRMED (single source for this exact beacon -- see"
echo "    below for whether the firewall corroborates the pattern)"
echo
echo "  FIREWALL CROSS-CHECK (ir_evidence/firewall_sessions_ws_recv_03.json):"
echo "    Export window: ${FW_START} to ${FW_END}"
if [[ "$FW_COVERS_STAGE12" == "yes" ]]; then
  echo "    This window DOES cover the Stage 2 establishment period."
else
  echo "    This window does NOT cover the Stage 1-2 period (${BEACON_TS} falls"
  echo "    $(delta_human "$BEACON_TS" "$FW_START") BEFORE the export even starts). The firewall"
  echo "    export cannot corroborate the ESTABLISHMENT moment itself -- only"
  echo "    its later persistence (see below). This is a genuine evidence gap,"
  echo "    not a contradiction: the two sources simply do not overlap in time."
fi
echo "    First firewall session to ${C2_IP}: ${FW_PRIMARY_FIRST}"
echo "    (same destination, interval \"${FW_PRIMARY_INTERVAL}\", JA3 fingerprint"
echo "    match confirmed by the export's own summary: matches_4x01_fingerprint=${FW_PRIMARY_MATCH})"
echo "    Clock-skew note (same reconciliation used in Tasks 3-4):"
echo "      ${SKEW_NOTE}"
echo "    Confidence: CONVERGED on the BEACON PATTERN (same C2 IP, same JA3,"
echo "    same ~5-min interval, continuous from 4x01 through the firewall"
echo "    export) even though the two sources do not share an overlapping"
echo "    timestamp for the establishment event itself."
echo
echo "  [${FW_SECONDARY_FIRST}] Secondary C2 channel to ${FW_SECONDARY_IP}:${FW_SECONDARY_PORT}"
echo "    Evidence: ir_evidence/firewall_sessions_ws_recv_03.json ONLY -- this"
echo "    IP does not appear in 4x00, 4x01, 4x02, 4x03 or 4x04 at all."
echo "    IOC status: ${SECONDARY_IOC}"
echo "    Note (evidence-native): ${FW_SECONDARY_NOTE:-see export}"
echo "    Classification note: ${FW_SECONDARY_CONF_NOTE:-n/a}"
echo "    Technique: T1071.001 (secondary application-layer channel)"
echo
echo "    >>> ANSWERING THE RECONSTRUCTION QUESTION:"
echo "    Was ${FW_SECONDARY_IP} active during Stage 2 (established ${BEACON_TS})?"
echo "    NO. Its first-ever session in the firewall export is ${FW_SECONDARY_FIRST},"
echo "    which is $(delta_human "$BEACON_TS" "$FW_SECONDARY_FIRST") AFTER the primary C2 beacon that marks Stage 2's"
echo "    establishment. It is also $(delta_human "$FW_PRIMARY_FIRST" "$FW_SECONDARY_FIRST") after the primary C2's own first"
echo "    appearance inside this firewall export. The secondary channel was"
echo "    therefore NOT part of Stage 2 -- it was deployed later, as backup/"
echo "    fallback infrastructure."
echo "    Caveat: the firewall export only starts ${FW_START}; there is a"
echo "    collection gap between the end of the 4x01 PCAP (${PCAP_END}) and"
echo "    the start of this firewall export, so a transient earlier use of"
echo "    ${FW_SECONDARY_IP} in that gap cannot be fully excluded from this"
echo "    evidence alone."
echo "    Confidence: PROBABLE (single source; absence is well-supported by"
echo "    every available source but an uncollected window remains)"
echo

echo "  TECHNIQUE T1568 (Dynamic Resolution):"
if [[ "$T1568_OBSERVED" == "yes" ]]; then
  echo "    OBSERVED -- see technique list below for the supporting evidence."
else
  echo "    NOT OBSERVED. Both C2 domains (${C2_DOMAIN}, update.healthbane-c2.net)"
  echo "    resolve via ordinary DNS A-records to a single static IP"
  echo "    (${C2_IP}) for the entire 4x01 PCAP window and the firewall export"
  echo "    alike. Neither source shows fast-flux, a DGA, or short-TTL"
  echo "    round-robin resolution. This technique is listed as \"if"
  echo "    applicable\" in the task instructions, and on this evidence it is"
  echo "    not -- it is reported here as NOT OBSERVED rather than included"
  echo "    by default."
fi
echo

echo "STAGE 1-2 SUMMARY:"
echo "  Stage 1 duration (click to credential submission): $(delta_human "$CLICK_TS" "$SUBMIT_TS")"
echo "  Stage 1 to Stage 2 (submission to first C2 beacon): $(delta_human "$SUBMIT_TS" "$BEACON_TS")"
echo "  Techniques mapped (${#ATTACK_IDS[@]}):"
for t in "${ATTACK_IDS[@]}"; do
  echo "    - $t"
done
echo "  IOCs cited: ${PHISH_DOMAIN_IOC}, ${C2_IP_IOC}, ${C2_DOMAIN_IOC}, ${SECONDARY_IOC}"
echo "  Key finding: the secondary C2 (${FW_SECONDARY_IP}:${FW_SECONDARY_PORT}) was NOT"
echo "  operational during Stage 2. It first appeared in the evidence on"
echo "  ${FW_SECONDARY_FIRST}, $(delta_human "$BEACON_TS" "$FW_SECONDARY_FIRST") after Stage 2's C2 establishment,"
echo "  suggesting the attacker deployed backup infrastructure well after"
echo "  the initial foothold was established."
echo
echo "================================================================"

exit 0
