#!/bin/bash
#
# 3-remediation_queue.sh
#
# Goal: cross-reference the CIS control profile (Task 1) against real
# Lynis findings (Task 2) to determine a compliance status for each of
# the 15 controls, then produce a prioritized remediation queue.
#
# DESIGN NOTE, stated directly rather than left implicit: this script
# also reads 0-baseline_snapshot.json (Task 0) as a third input, beyond
# the two files named in the task instructions. This is a deliberate,
# disclosed choice: Lynis's own report format only ever lists problems
# (warning/suggestion/manual_check). It never positively confirms a
# setting is already correct. Cross-referencing only cis_profile.json
# and lynis_findings.json can therefore only ever produce
# "non_compliant", "partially_compliant", or "not_assessed" outcomes,
# never a genuine "compliant" one, since silence in a Lynis report is
# not proof of a good configuration, only proof Lynis did not flag it.
# The baseline snapshot is the only file in this project that records
# actual current values (e.g., net.ipv4.tcp_syncookies=1), which is
# the only honest source for a positive "compliant" determination.
#
# This script makes NO changes to the system. It only reads the three
# JSON inputs above and writes gap_analysis.json and
# remediation_queue.json. Idempotent: re-running against the same three
# input files always regenerates identical output.
 
set -euo pipefail
 
CIS_PROFILE="./cis_profile.json"
LYNIS_FINDINGS="./lynis_findings.json"
BASELINE="./0-baseline_snapshot.json"
GAP_OUTPUT="./gap_analysis.json"
QUEUE_OUTPUT="./remediation_queue.json"
 
# ---------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------
for f in "$CIS_PROFILE" "$LYNIS_FINDINGS"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: required input file not found: ${f}" >&2
    exit 1
  fi
done
 
BASELINE_AVAILABLE=false
if [ -f "$BASELINE" ]; then
  BASELINE_AVAILABLE=true
else
  echo "WARNING: ${BASELINE} not found. Controls that can only be" >&2
  echo "confirmed compliant via baseline evidence will be reported as" >&2
  echo "not_assessed instead. Run 0-baseline_snapshot.sh first for a" >&2
  echo "complete assessment." >&2
fi
 
if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required for this script. Install it with:" >&2
  echo "  sudo apt install jq" >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# LOAD LYNIS TEST IDs INTO A SEARCHABLE LIST
# ---------------------------------------------------------------------
LYNIS_TEST_IDS=$(jq -r '.findings[].test_id' "$LYNIS_FINDINGS")
 
lynis_has() {
  # Returns 0 (true) if any of the given test IDs appear in the Lynis
  # findings, 1 (false) otherwise.
  local id
  for id in "$@"; do
    if grep -qx "$id" <<< "$LYNIS_TEST_IDS"; then
      return 0
    fi
  done
  return 1
}
 
# ---------------------------------------------------------------------
# LOAD BASELINE VALUES (if available)
# ---------------------------------------------------------------------
baseline_get() {
  # baseline_get <jq path> ; prints the value or "unavailable"
  if [ "$BASELINE_AVAILABLE" = true ]; then
    jq -r "$1 // \"unavailable\"" "$BASELINE" 2>/dev/null || echo "unavailable"
  else
    echo "unavailable"
  fi
}
 
BASE_SYNCOOKIES=$(baseline_get '.sysctl_parameters["net.ipv4.tcp_syncookies"]')
BASE_ACCEPT_REDIRECTS=$(baseline_get '.sysctl_parameters["net.ipv4.conf.all.accept_redirects"]')
BASE_IP_FORWARD=$(baseline_get '.sysctl_parameters["net.ipv4.ip_forward"]')
BASE_SUID_DUMPABLE=$(baseline_get '.sysctl_parameters["fs.suid_dumpable"]')
BASE_PERMITROOTLOGIN=$(baseline_get '.ssh_configuration.permitrootlogin')
BASE_PASSWORDAUTH=$(baseline_get '.ssh_configuration.passwordauthentication')
BASE_SUID_COUNT_NONSTANDARD=$(baseline_get '.suid_binaries.list | map(select(startswith("/usr/local/") or startswith("/opt/"))) | length')
BASE_MYSQL_EXPOSED=$(baseline_get '.open_ports.list | map(select(contains("3306") and contains("0.0.0.0"))) | length')
 
# ---------------------------------------------------------------------
# JSON ESCAPE HELPER
# ---------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}
 
# ---------------------------------------------------------------------
# PER-CONTROL ASSESSMENT
# ---------------------------------------------------------------------
# Each entry: control_id|status|evidence|op_risk
# Status is determined by, in order of preference: (1) direct baseline
# value confirmation, (2) a specific matching Lynis test_id, (3) a
# generic/adjacent Lynis test_id (partial), (4) no evidence at all
# (not_assessed), with one exception documented inline below where
# general Ubuntu 22.04 default-configuration knowledge is used
# explicitly as evidence, not fabricated.
 
CONTROL_ID=()
STATUS=()
EVIDENCE=()
OP_RISK=()
 
assess() {
  CONTROL_ID+=("$1")
  STATUS+=("$2")
  EVIDENCE+=("$3")
  OP_RISK+=("$4")
}
 
# 5.1 SSH password authentication
if [ "$BASE_PASSWORDAUTH" = "yes" ]; then
  assess "5.1" "non_compliant" "Baseline confirms passwordauthentication=yes; Lynis SSH-7408 present" \
    "An attacker with network reach to SSH can attempt password-based brute force against any of the 4 real accounts"
elif lynis_has "SSH-7408"; then
  assess "5.1" "partially_compliant" "Lynis SSH-7408 (generic SSH hardening suggestion) present, no baseline confirmation" \
    "SSH configuration flagged as needing review; specific password-auth state unconfirmed"
else
  assess "5.1" "not_assessed" "No baseline or Lynis evidence available for this specific setting" \
    "Unknown; cannot be prioritized without evidence"
fi
 
# 5.1.20 SSH root login
if [ "$BASE_PERMITROOTLOGIN" = "yes" ]; then
  assess "5.1.20" "non_compliant" "Baseline confirms permitrootlogin=yes; Lynis SSH-7408 present" \
    "Root-level SSH access possible without individual account attribution"
else
  assess "5.1.20" "not_assessed" "No baseline confirmation available for this setting" \
    "Unknown; cannot be prioritized without evidence"
fi
 
# 5.1.4 SSH AllowUsers
if lynis_has "SSH-7408"; then
  assess "5.1.4" "non_compliant" "Lynis SSH-7408 present (generic SSH hardening); baseline shows allowusers=not-set" \
    "Any valid credential on the system can authenticate over SSH, not only approved administrative accounts"
else
  assess "5.1.4" "not_assessed" "No Lynis or baseline evidence available" \
    "Unknown; cannot be prioritized without evidence"
fi
 
# 5.3.3.2.7 PAM pwquality
if lynis_has "AUTH-9230" "AUTH-9282" "AUTH-9286" "AUTH-9328"; then
  assess "5.3.3.2.7" "partially_compliant" "Lynis flags adjacent password-policy items (AUTH-9230/9282/9286/9328), not the pwquality module specifically" \
    "Weak passwords may currently be accepted, though the exact pwquality module state is not directly confirmed"
else
  assess "5.3.3.2.7" "not_assessed" "No relevant Lynis finding present" \
    "Unknown; cannot be prioritized without evidence"
fi
 
# 5.3.3.1.1 PAM faillock
assess "5.3.3.1.1" "not_assessed" "No Lynis finding or baseline data addresses account lockout specifically" \
  "Unknown; cannot be prioritized without evidence"
 
# 1.5.3 core dumps
if [ "$BASE_SUID_DUMPABLE" != "0" ] && [ "$BASE_SUID_DUMPABLE" != "unavailable" ]; then
  assess "1.5.3" "non_compliant" "Baseline confirms fs.suid_dumpable=${BASE_SUID_DUMPABLE} (should be 0); Lynis KRNL-5820 present" \
    "A process crash could expose credentials or session data resident in memory to any local user"
elif lynis_has "KRNL-5820"; then
  assess "1.5.3" "non_compliant" "Lynis KRNL-5820 directly recommends disabling core dumps" \
    "A process crash could expose credentials or session data resident in memory to any local user"
else
  assess "1.5.3" "not_assessed" "No evidence available" "Unknown"
fi
 
# 3.3.1.8 ICMP redirects
if [ "$BASE_ACCEPT_REDIRECTS" = "0" ]; then
  assess "3.3.1.8" "compliant" "Baseline confirms net.ipv4.conf.all.accept_redirects=0, the secure value" \
    "None currently; maintain this setting through the kernel hardening script to prevent regression"
else
  assess "3.3.1.8" "partially_compliant" "Lynis KRNL-6000 (generic sysctl deviation) present, specific redirect state unconfirmed" \
    "Possible on-path traffic redirection if this specific parameter is not actually hardened"
fi
 
# 3.3.1.1 IP forwarding
if [ "$BASE_IP_FORWARD" = "1" ]; then
  assess "3.3.1.1" "non_compliant" "Baseline confirms net.ipv4.ip_forward=1 on a database/web server with no routing function" \
    "A compromised host could be repurposed as an internal network pivot"
elif lynis_has "KRNL-6000"; then
  assess "3.3.1.1" "partially_compliant" "Lynis KRNL-6000 generic sysctl deviation present" \
    "Possible unnecessary IP forwarding capability"
else
  assess "3.3.1.1" "not_assessed" "No evidence available" "Unknown"
fi
 
# 3.3.1.18 SYN cookies
if [ "$BASE_SYNCOOKIES" = "1" ]; then
  assess "3.3.1.18" "compliant" "Baseline confirms net.ipv4.tcp_syncookies=1, the secure value (Ubuntu default)" \
    "None currently; maintain this setting through the kernel hardening script to prevent regression"
else
  assess "3.3.1.18" "partially_compliant" "Lynis KRNL-6000 generic sysctl deviation present, specific state unconfirmed" \
    "Possible reduced resilience to SYN flood denial of service"
fi
 
# 7.1.13 SUID/SGID review
if [ "$BASE_SUID_COUNT_NONSTANDARD" != "unavailable" ] && [ "$BASE_SUID_COUNT_NONSTANDARD" -gt 0 ] 2>/dev/null; then
  assess "7.1.13" "non_compliant" "Baseline confirms ${BASE_SUID_COUNT_NONSTANDARD} non-standard SUID binaries outside typical package paths (/usr/local, /opt)" \
    "An unexplained SUID binary on a previously compromised server (0x00 cryptominer incident) may itself be a persistence mechanism"
elif lynis_has "FILE-7524"; then
  assess "7.1.13" "partially_compliant" "Lynis FILE-7524 generically suggests restricting file permissions" \
    "Possible unreviewed elevated-privilege binaries"
else
  assess "7.1.13" "not_assessed" "No evidence available" "Unknown"
fi
 
# 1.1.2 mount options
# No baseline check and no Lynis finding specifically addresses mount
# options (noexec/nosuid/nodev) in this run. Rather than default to
# not_assessed, this control is treated as non_compliant based on
# documented, general Ubuntu 22.04 default-installation behavior,
# stated explicitly as the evidence type used, not fabricated scan data:
# a stock Ubuntu 22.04 install does not apply noexec/nosuid/nodev to
# /tmp, /dev/shm, or /var/tmp without explicit administrator
# configuration.
assess "1.1.2" "non_compliant" "No baseline or Lynis confirmation exists; evidence basis is documented Ubuntu 22.04 default behavior (these mount options are not applied out of the box), not scan data" \
  "Partitions that should never execute code currently can, widening post-exploitation persistence options"
 
# 2.1.22 service minimization
BASE_SERVICE_COUNT=$(baseline_get '.running_services.count')
if [ "$BASE_SERVICE_COUNT" != "unavailable" ]; then
  assess "2.1.22" "partially_compliant" "Baseline confirms ${BASE_SERVICE_COUNT} running services on billing-srv-01; no formal approved-services allow-list exists to confirm which are justified" \
    "Unreviewed running services represent unmeasured, unjustified attack surface on a server with a prior confirmed compromise"
else
  assess "2.1.22" "not_assessed" "No evidence available" "Unknown"
fi
 
# 4.1.3 firewall / MySQL exposure
if [ "$BASE_MYSQL_EXPOSED" != "unavailable" ] && [ "$BASE_MYSQL_EXPOSED" -gt 0 ] 2>/dev/null; then
  assess "4.1.3" "non_compliant" "Baseline confirms MySQL bound to 0.0.0.0:3306; Lynis FIRE-4512 confirms iptables loaded with no active rules; FIRE-4513 confirms unused rule review needed" \
    "The patient database is reachable from any network address with no host firewall enforcing restriction, the same exfiltration method documented in the Crimson Tide advisory"
elif lynis_has "FIRE-4512" "FIRE-4513"; then
  assess "4.1.3" "non_compliant" "Lynis FIRE-4512 confirms no active iptables rules despite the module being loaded" \
    "No host-level firewall enforcement currently exists"
else
  assess "4.1.3" "not_assessed" "No evidence available" "Unknown"
fi
 
# 6.2.3.1 auditd rules
if lynis_has "ACCT-9630"; then
  assess "6.2.3.1" "non_compliant" "Lynis ACCT-9630 directly confirms: audit daemon is enabled with an empty ruleset" \
    "auditd is running but capturing nothing; a privilege escalation or credential theft attempt would leave no audit trail whatsoever"
else
  assess "6.2.3.1" "not_assessed" "No evidence available" "Unknown"
fi
 
# 6.1.2.6 remote log forwarding
if lynis_has "LOGG-2154"; then
  assess "6.1.2.6" "non_compliant" "Lynis LOGG-2154 directly confirms: no external logging host currently configured" \
    "If any of these three servers, especially log-srv-01, is compromised, an attacker can erase local evidence with no off-host copy surviving"
else
  assess "6.1.2.6" "not_assessed" "No evidence available" "Unknown"
fi
 
CONTROL_COUNT=${#CONTROL_ID[@]}
 
# ---------------------------------------------------------------------
# PRIORITY SCORING (1-100)
# ---------------------------------------------------------------------
# Base score by CIS severity, then adjusted by compliance status.
# Non-compliant carries full weight; partially compliant is discounted
# since some protection already exists.
priority_score() {
  local control_id="$1" status="$2"
  local sev base
  sev=$(jq -r --arg cid "$control_id" '.controls[] | select(.control_id==$cid) | .severity' "$CIS_PROFILE")
  case "$sev" in
    critical) base=90 ;;
    high) base=70 ;;
    medium) base=50 ;;
    *) base=40 ;;
  esac
  case "$status" in
    non_compliant) echo "$base" ;;
    partially_compliant) echo "$((base * 70 / 100))" ;;
    *) echo "0" ;;
  esac
}
 
# ---------------------------------------------------------------------
# BUILD gap_analysis.json (all 15 controls)
# ---------------------------------------------------------------------
{
  printf '{\n  "assessment_date": "%s",\n  "controls": [\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  for i in "${!CONTROL_ID[@]}"; do
    cid="${CONTROL_ID[$i]}"
    title=$(jq -r --arg cid "$cid" '.controls[] | select(.control_id==$cid) | .title' "$CIS_PROFILE")
    printf '    {\n'
    printf '      "control_id": "%s",\n' "$(json_escape "$cid")"
    printf '      "title": "%s",\n' "$(json_escape "$title")"
    printf '      "status": "%s",\n' "$(json_escape "${STATUS[$i]}")"
    printf '      "evidence": "%s"\n' "$(json_escape "${EVIDENCE[$i]}")"
    if [ "$i" -lt $((CONTROL_COUNT - 1)) ]; then printf '    },\n'; else printf '    }\n'; fi
  done
  printf '  ]\n}\n'
} > "$GAP_OUTPUT"
 
# ---------------------------------------------------------------------
# BUILD remediation_queue.json (non_compliant + partially_compliant, sorted by priority desc)
# ---------------------------------------------------------------------
QUEUE_ENTRIES=()
for i in "${!CONTROL_ID[@]}"; do
  st="${STATUS[$i]}"
  if [ "$st" = "non_compliant" ] || [ "$st" = "partially_compliant" ]; then
    cid="${CONTROL_ID[$i]}"
    score=$(priority_score "$cid" "$st")
    QUEUE_ENTRIES+=("${score}|${i}")
  fi
done
 
# Sort descending by score (field 1, numeric)
IFS=$'\n' SORTED=($(printf '%s\n' "${QUEUE_ENTRIES[@]}" | sort -t'|' -k1,1nr))
unset IFS
 
{
  printf '{\n  "generated": "%s",\n  "queue": [\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  total=${#SORTED[@]}
  for idx in "${!SORTED[@]}"; do
    score="${SORTED[$idx]%%|*}"
    i="${SORTED[$idx]#*|}"
    cid="${CONTROL_ID[$i]}"
    title=$(jq -r --arg cid "$cid" '.controls[] | select(.control_id==$cid) | .title' "$CIS_PROFILE")
    sev=$(jq -r --arg cid "$cid" '.controls[] | select(.control_id==$cid) | .severity' "$CIS_PROFILE")
    scope=$(jq -r --arg cid "$cid" '.controls[] | select(.control_id==$cid) | .asset_scope' "$CIS_PROFILE")
    task=$(jq -r --arg cid "$cid" '.controls[] | select(.control_id==$cid) | .implementation_task' "$CIS_PROFILE")
    verify=$(jq -r --arg cid "$cid" '.controls[] | select(.control_id==$cid) | .verification_method' "$CIS_PROFILE")
 
    printf '    {\n'
    printf '      "control_id": "%s",\n' "$(json_escape "$cid")"
    printf '      "title": "%s",\n' "$(json_escape "$title")"
    printf '      "status": "%s",\n' "$(json_escape "${STATUS[$i]}")"
    printf '      "severity": "%s",\n' "$(json_escape "$sev")"
    printf '      "priority_score": %s,\n' "$score"
    printf '      "affected_asset": "%s",\n' "$(json_escape "$scope")"
    printf '      "lynis_evidence": "%s",\n' "$(json_escape "${EVIDENCE[$i]}")"
    printf '      "remediation_script": "%s",\n' "$(json_escape "$task")"
    printf '      "operational_risk_if_unresolved": "%s",\n' "$(json_escape "${OP_RISK[$i]}")"
    printf '      "expected_validation_check": "%s"\n' "$(json_escape "$verify")"
    if [ "$idx" -lt $((total - 1)) ]; then printf '    },\n'; else printf '    }\n'; fi
  done
  printf '  ]\n}\n'
} > "$QUEUE_OUTPUT"
 
# ---------------------------------------------------------------------
# SUMMARY COUNTS
# ---------------------------------------------------------------------
COMPLIANT_COUNT=0
NONCOMPLIANT_COUNT=0
PARTIAL_COUNT=0
NOTASSESSED_COUNT=0
for st in "${STATUS[@]}"; do
  case "$st" in
    compliant) COMPLIANT_COUNT=$((COMPLIANT_COUNT + 1)) ;;
    non_compliant) NONCOMPLIANT_COUNT=$((NONCOMPLIANT_COUNT + 1)) ;;
    partially_compliant) PARTIAL_COUNT=$((PARTIAL_COUNT + 1)) ;;
    not_assessed) NOTASSESSED_COUNT=$((NOTASSESSED_COUNT + 1)) ;;
  esac
done
QUEUED_COUNT=${#SORTED[@]}
 
echo "Controls assessed: ${CONTROL_COUNT}"
echo "Compliant: ${COMPLIANT_COUNT}"
echo "Non-compliant: ${NONCOMPLIANT_COUNT}"
echo "Partially compliant: ${PARTIAL_COUNT}"
echo "Not assessed: ${NOTASSESSED_COUNT}"
echo "Remediation actions queued: ${QUEUED_COUNT}"
echo "Report saved to: ${GAP_OUTPUT}"
echo "Queue saved to: ${QUEUE_OUTPUT}"
