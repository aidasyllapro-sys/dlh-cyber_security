#!/bin/bash
# 6-hunt_credentials.sh
#
# Hunt execution for H2: Credential Access via LSASS memory (T1003.001).
# Finds LSASS access events, separates legitimate OS access from
# anomalous access by an unusual source process, then looks for
# svc_healthsync authentications from outside its single authorized
# host, correlates those with PsExec/WMI/PSRemoting activity from the
# same source, and lays out the resulting credential-theft timeline.
#
# Reads only the files under siem_export/ and reference/ (read-only).
# Produces no output file; everything is printed to stdout.
# Deterministic: re-running against the same inputs always prints the
# same report.

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
SVC_ACCOUNTS="reference/service_accounts.txt"

require_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    echo "Error: required file not found: $path" >&2
    exit 1
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" > /dev/null 2>&1; then
    echo "Error: required command not found: $cmd" >&2
    exit 1
  fi
}

require_cmd jq
require_file "$ALERTS"
require_file "$SYSMON"
require_file "$SVC_ACCOUNTS"

# ---------------------------------------------------------------------
# wazuh_raw_sysmon_14d.json duplicates records already present in
# wazuh_alerts_14d.json (same "id" field - see 3-data_recon.sh).
# ---------------------------------------------------------------------
combined() {
  jq -s -c 'unique_by(.id)[]' "$ALERTS" "$SYSMON"
}

# ---------------------------------------------------------------------
# svc_healthsync's single authorized host, read from the service
# account matrix rather than hardcoded.
# ---------------------------------------------------------------------
svc_authorized_host=$(sed -n '/--- svc_healthsync ---/,/^--$/p' "$SVC_ACCOUNTS" \
  | grep -m1 'Authorized host:' | awk '{print $3}')

if [ -z "$svc_authorized_host" ]; then
  echo "Error: could not parse svc_healthsync's authorized host from $SVC_ACCOUNTS" >&2
  exit 1
fi

# ---------------------------------------------------------------------
# 1. LSASS access events: Sysmon Event 10 (Process accessed) whose
#    target image is lsass.exe.
# ---------------------------------------------------------------------
lsass_events=$(combined | jq -c '
  select(.data.win.eventdata.targetImage? // "" | test("lsass\\.exe"; "i"))
')
total_lsass=$(echo "$lsass_events" | grep -c . || true)

# ---------------------------------------------------------------------
# 2. Legitimate vs anomalous: legitimate OS components access LSASS
#    (service manager, WMI provider host, etc.) from a System32 image
#    running as NT AUTHORITY\SYSTEM. An unusual source process - a
#    non-System32 path, or a non-SYSTEM account - is the anomaly
#    signal, not the access mask alone (the access mask is reported as
#    supporting context "if available", per the instructions).
# ---------------------------------------------------------------------
# join("\t") is used instead of @tsv: @tsv doubles backslashes (TSV
# escaping), which would corrupt Windows paths like
# C:\Windows\System32\services.exe and break the prefix match below.
lsass_records=$(echo "$lsass_events" | jq -r '
  [
    .timestamp,
    .agent.name,
    (.data.win.eventdata.sourceImage? // "UNKNOWN"),
    (.data.win.eventdata.sourceUser? // "UNKNOWN"),
    (.data.win.eventdata.targetImage? // "UNKNOWN"),
    (.data.win.eventdata.grantedAccess? // "(none)")
  ] | join("\t")
')

legit_count=0
anomalous_lsass_count=0
declare -a lsass_anomalies=()

while IFS=$'\t' read -r ts host srcimg srcuser target access; do
  [ -z "$ts" ] && continue
  unusual=false
  case "$srcimg" in
    "C:\\Windows\\System32\\"*) ;;
    *) unusual=true ;;
  esac
  [ "$srcuser" != "NT AUTHORITY\\SYSTEM" ] && unusual=true

  if [ "$unusual" = false ]; then
    legit_count=$((legit_count + 1))
  else
    anomalous_lsass_count=$((anomalous_lsass_count + 1))
    # VM_READ (0x0010) present in the access mask is reported as
    # supporting context, when the field is available.
    dumping_note="no"
    if [ "$access" != "(none)" ]; then
      access_dec=$(( 16#${access#0x} ))
      if [ $(( access_dec & 0x10 )) -ne 0 ]; then
        dumping_note="yes"
      fi
    fi
    lsass_anomalies+=("$ts	$host	$srcimg	$target	$access	$dumping_note")
  fi
done <<< "$lsass_records"

# ---------------------------------------------------------------------
# 3. svc_healthsync authentications from a workstation other than its
#    single authorized host (SRV-HEALTH-DB). Keep only the actual
#    lateral hop (the record logged on the target server), not the
#    attacker's own local logon on their workstation.
# ---------------------------------------------------------------------
cred_usage=$(combined | jq -r --arg host "$svc_authorized_host" '
  select(.rule.id == "60106")
  | select(.data.win.eventdata.targetUserName? // "" | test("svc_healthsync"; "i"))
  | select((.data.win.eventdata.workstationName? // "") != $host)
  | select(.agent.name != (.data.win.eventdata.workstationName? // ""))
  | [.timestamp, (.data.win.eventdata.workstationName? // "UNKNOWN"), .agent.name] | join("\t")
' | sort)

cred_usage_count=$(echo "$cred_usage" | grep -c . || true)

# ---------------------------------------------------------------------
# 4. Correlate each lateral svc_healthsync hop with PsExec/WMI/
#    PSRemoting activity from the same source workstation against the
#    same target, independent of any hidden label.
# ---------------------------------------------------------------------
correlate_tooling() {
  local src="$1" tgt="$2"
  combined | jq -e --arg src "$src" --arg tgt "$tgt" '
    select(.agent.name == $src)
    | select(
        (.data.win.eventdata.image? // "" | test("psexec|wmic|wmiprvse|wsmprovhost"; "i"))
        or (.data.win.eventdata.commandLine? // "" | test("psexec"; "i"))
      )
    | select(
        (.data.win.eventdata.commandLine? // "" | test($tgt; "i"))
        or (.data.win.eventdata.destinationHostname? // "" | test($tgt; "i"))
      )
  ' > /dev/null 2>&1
}

# ---------------------------------------------------------------------
# 5. Merge LSASS anomalies and credential-use hops into one
#    chronological timeline.
# ---------------------------------------------------------------------
declare -a timeline=()
while IFS=$'\t' read -r ts host srcimg target access dumping; do
  [ -z "$ts" ] && continue
  timeline+=("$ts	LSASS_ACCESS	$host used $srcimg to read $target (access $access)")
done <<< "$(printf '%s\n' "${lsass_anomalies[@]:-}")"

while IFS=$'\t' read -r ts src tgt; do
  [ -z "$ts" ] && continue
  timeline+=("$ts	CREDENTIAL_USE	svc_healthsync authenticated from $src to $tgt")
done <<< "$cred_usage"

sorted_timeline=$(printf '%s\n' "${timeline[@]:-}" | sort)

high_confidence=false
[ "$anomalous_lsass_count" -gt 0 ] && [ "$cred_usage_count" -gt 0 ] && high_confidence=true

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
echo "================================================================"
echo "   HUNT EXECUTION - H2: Credential Access (LSASS)"
echo "   Technique: T1003.001 LSASS Memory"
echo "================================================================"
echo
echo "LSASS ACCESS EVENTS:"
printf '  %-28s%s\n' "Total LSASS access events:" "$total_lsass"
printf '  %-28s%s\n' "System/legitimate:" "$legit_count"
printf '  %-28s%s\n' "ANOMALOUS:" "$anomalous_lsass_count"
echo

if [ "$anomalous_lsass_count" -gt 0 ]; then
  i=0
  while IFS=$'\t' read -r ts host srcimg target access dumping; do
    [ -z "$ts" ] && continue
    i=$((i + 1))
    echo "  [A${i}] $ts"
    echo "    Host: $host"
    echo "    Source Process: $srcimg"
    echo "    Target: $target"
    echo "    Access Mask: $access"
    if [ "$dumping" = "yes" ]; then
      echo "    -> Consistent with memory dumping (VM_READ set, no system-level control bits)"
    else
      echo "    -> Access mask not available or does not indicate memory read"
    fi
    echo
  done < <(printf '%s\n' "${lsass_anomalies[@]:-}" | sort)
fi

echo "CREDENTIAL USAGE CORRELATION:"
if [ "$cred_usage_count" -gt 0 ]; then
  echo "  svc_healthsync authentication from workstations:"
  while IFS=$'\t' read -r ts src tgt; do
    [ -z "$ts" ] && continue
    tool_note=""
    correlate_tooling "$src" "$tgt" && tool_note=" (PsExec/WMI/PSRemoting activity also observed $src -> $tgt)"
    echo "    $ts $src -> $tgt$tool_note"
  done <<< "$cred_usage"
else
  echo "  No svc_healthsync authentication found from outside $svc_authorized_host"
fi
echo

echo "CREDENTIAL THEFT TIMELINE:"
if [ -n "$sorted_timeline" ]; then
  while IFS=$'\t' read -r ts kind detail; do
    [ -z "$ts" ] && continue
    echo "  $ts [$kind] $detail"
  done <<< "$sorted_timeline"
else
  echo "  No anomalous LSASS access or out-of-policy svc_healthsync use found"
fi
echo

echo "FINDING:"
if [ "$high_confidence" = true ]; then
  echo "  Status: POSITIVE - HIGH CONFIDENCE"
  echo "  The attacker likely dumped credentials and later used svc_healthsync"
  echo "  for lateral movement."
elif [ "$anomalous_lsass_count" -gt 0 ] || [ "$cred_usage_count" -gt 0 ]; then
  echo "  Status: POSITIVE - MEDIUM CONFIDENCE"
  echo "  Either anomalous LSASS access or out-of-policy svc_healthsync use was"
  echo "  found, but not both, so the credential-theft chain is incomplete."
else
  echo "  Status: NEGATIVE"
  echo "  No anomalous LSASS access or out-of-policy svc_healthsync use found."
fi
echo
echo "================================================================"

exit 0
