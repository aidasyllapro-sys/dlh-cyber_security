#!/bin/bash
# 4-hunt_psexec.sh
#
# Hunt execution for H1: Lateral Movement via PsExec (T1021.002 SMB/
# Windows Admin Shares). Extracts every PsExec-related event from the
# SIEM export, classifies each one against Robert Kim's administrative
# baseline (source host, time of day, day of week, user account), and
# reports a hunt finding with a confidence assessment.
#
# Classification is behavioral: it is computed independently, from the
# same four criteria admin_schedule.txt documents, not from any hidden
# label the dataset happens to carry. It is not read from any
# "category"/"authorized" style field.
#
# Reads only the files under siem_export/, baseline/ and reference/
# (read-only). Produces no output file; everything is printed to
# stdout. Deterministic: re-running against the same inputs always
# prints the same report.

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
BASELINE="baseline/robert_kim_activity.json"
ADMIN_SCHEDULE="reference/admin_schedule.txt"

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
require_file "$BASELINE"
require_file "$ADMIN_SCHEDULE"

# ---------------------------------------------------------------------
# wazuh_raw_sysmon_14d.json duplicates records already present in
# wazuh_alerts_14d.json (same "id" field - see 3-data_recon.sh). Dedupe
# before counting so a PsExec action is not reported twice.
# ---------------------------------------------------------------------
combined() {
  jq -s -c 'unique_by(.id)[]' "$ALERTS" "$SYSMON"
}

# ---------------------------------------------------------------------
# Baseline criteria, read from the schedule document instead of
# hardcoded (same approach as 2-baseline_profile.sh).
# ---------------------------------------------------------------------
admin_workstation=$(grep -m1 '^Workstation:' "$ADMIN_SCHEDULE" | awk '{print $2}')
work_hours_line=$(grep -m1 '^Work hours:' "$ADMIN_SCHEDULE")
hour_start=$(echo "$work_hours_line" | grep -oE '[0-9]{2}:[0-9]{2}' | sed -n '1p' | cut -d: -f1)
hour_end=$(echo "$work_hours_line" | grep -oE '[0-9]{2}:[0-9]{2}' | sed -n '2p' | cut -d: -f1)

if [ -z "$admin_workstation" ] || [ -z "$hour_start" ] || [ -z "$hour_end" ]; then
  echo "Error: could not parse workstation/work-hours from $ADMIN_SCHEDULE" >&2
  exit 1
fi

# Cross-check only (not used for classification): how many of Robert
# Kim's own documented baseline events are PsExec, for context.
baseline_psexec_count=$(jq -s '[.[] | select(.hunt_meta.tool == "PsExec")] | length' "$BASELINE")

# ---------------------------------------------------------------------
# 1. Extract all PsExec-related events: image or commandLine contains
#    "psexec" (case-insensitive).
# ---------------------------------------------------------------------
psexec_events=$(combined | jq -c '
  select(
    (.data.win.eventdata.image? // "" | test("psexec"; "i"))
    or (.data.win.eventdata.commandLine? // "" | test("psexec"; "i"))
  )
')

total_psexec=$(echo "$psexec_events" | grep -c . || true)

# ---------------------------------------------------------------------
# Target-host extraction: parse the UNC path out of the command line
# (\\HOSTNAME), falling back to the network event's destination
# hostname, then to the hunt_meta annotation if neither observable
# field is present. Derived from evidence, not assumed.
# ---------------------------------------------------------------------
# shellcheck disable=SC2016  # single-quoted on purpose: this is jq source, not a shell variable
jq_target_fn='
  def cmdtarget:
    (.data.win.eventdata.commandLine? // "") as $c
    | (($c | capture("\\\\\\\\(?<h>[A-Za-z0-9.-]+)")) // null) as $m
    | if $m != null then $m.h
      elif (.data.win.eventdata.destinationHostname? // null) != null then .data.win.eventdata.destinationHostname
      else (.hunt_meta.target_host? // "UNKNOWN")
      end;
'

# ---------------------------------------------------------------------
# 2 & 3. Compare each event to the baseline and classify. For each
#    event, emit: timestamp, source host, user, commandLine, target,
#    pid, then one flag per baseline criterion that is violated.
#    Fields are tab-separated; "(none)" marks an absent commandLine/pid
#    so the record stays parseable.
# ---------------------------------------------------------------------
records=$(echo "$psexec_events" | jq -r "
  $jq_target_fn
  [
    .timestamp,
    .agent.name,
    (.data.win.eventdata.user? // \"UNKNOWN\"),
    (.data.win.eventdata.commandLine? // \"(none)\"),
    cmdtarget,
    (.data.win.eventdata.processId? // \"(none)\")
  ] | @tsv
")

baseline_count=0
anomalous_count=0
declare -a anomalous_records=()

while IFS=$'\t' read -r ts src user cmd target pid; do
  [ -z "$ts" ] && continue
  local_hour=$(TZ=America/Chicago date -d "$ts" +%H)
  local_day=$(TZ=America/Chicago date -d "$ts" +%a)

  # The four baseline criteria from admin_schedule.txt decide BASELINE
  # vs ANOMALOUS. The database-naming check below is informational
  # context only - it never classifies an otherwise-compliant event as
  # anomalous on its own (an admin pushing a patch to SRV-HEALTH-DB
  # from WS-ADMIN-01 during business hours is normal baseline work).
  flags=()
  [ "$src" != "$admin_workstation" ] && flags+=("Source host is NOT $admin_workstation")
  if [ "$((10#$local_hour))" -lt "$((10#$hour_start))" ] || [ "$((10#$local_hour))" -ge "$((10#$hour_end))" ]; then
    flags+=("Time is outside business hours (${hour_start}:00-${hour_end}:00 CT)")
  fi
  if [ "$local_day" = "Sat" ] || [ "$local_day" = "Sun" ]; then
    flags+=("Day is $local_day (weekend)")
  fi
  if echo "$user" | grep -qi 'svc_'; then
    flags+=("User is a service account")
  fi

  if [ "${#flags[@]}" -eq 0 ]; then
    baseline_count=$((baseline_count + 1))
  else
    if echo "$target" | grep -qiE -- '-DB$'; then
      flags+=("Target follows database-server naming convention (${target})")
    fi
    anomalous_count=$((anomalous_count + 1))
    flag_str=$(printf '%s\n' "${flags[@]}" | paste -sd '|')
    anomalous_records+=("$ts	$src	$user	$cmd	$target	$pid	$flag_str")
  fi
done <<< "$records"

# ---------------------------------------------------------------------
# 4. Sort anomalous events chronologically and print [A1], [A2], ...
# ---------------------------------------------------------------------
sorted_anomalies=$(printf '%s\n' "${anomalous_records[@]:-}" | sort)

high_confidence=false
if printf '%s\n' "${anomalous_records[@]:-}" \
  | grep -qi 'Source host is NOT' && printf '%s\n' "${anomalous_records[@]:-}" | grep -qi 'service account'; then
  high_confidence=true
fi

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
echo "================================================================"
echo "   HUNT EXECUTION - H1: Lateral Movement via PsExec"
echo "   Technique: T1021.002 SMB/Windows Admin Shares"
echo "================================================================"
echo
echo "QUERY RESULTS:"
printf '  %-32s%s\n' "Total PsExec events in 14 days:" "$total_psexec"
printf '  %-32s%s\n' "Baseline:" "$baseline_count"
printf '  %-32s%s\n' "ANOMALOUS:" "$anomalous_count"
printf '  %-32s%s (cross-check only, not used for classification)\n' "Robert Kim baseline PsExec use:" "$baseline_psexec_count"
echo

if [ "$anomalous_count" -gt 0 ]; then
  echo "ANOMALOUS EVENTS:"
  i=0
  while IFS=$'\t' read -r ts src user cmd target pid flag_str; do
    [ -z "$ts" ] && continue
    i=$((i + 1))
    echo "  [A${i}] $ts"
    echo "    Source: $src"
    echo "    User: $user"
    echo "    Command: $cmd"
    echo "    Target: $target"
    echo "    PID: $pid"
    echo "    ANOMALY FLAGS:"
    IFS='|' read -ra flag_arr <<< "$flag_str"
    for f in "${flag_arr[@]}"; do
      echo "      [!] $f"
    done
    echo
  done <<< "$sorted_anomalies"
fi

echo "FINDING:"
if [ "$anomalous_count" -eq 0 ]; then
  echo "  Status: NEGATIVE"
  echo "  Evidence: All PsExec activity matches Robert Kim's documented baseline"
  echo "  Recommendation: NO ACTION"
elif [ "$high_confidence" = true ]; then
  echo "  Status: POSITIVE - HIGH CONFIDENCE"
  echo "  Evidence: PsExec executions from a non-admin workstation using a service account"
  echo "  Recommendation: ESCALATE"
else
  echo "  Status: POSITIVE - MEDIUM CONFIDENCE"
  echo "  Evidence: PsExec activity deviates from the documented baseline, but without the combined non-admin-host-plus-service-account signal"
  echo "  Recommendation: INVESTIGATE"
fi
echo
echo "================================================================"

exit 0
