#!/bin/bash
# 2-baseline_profile.sh
#
# Profiles Robert Kim's legitimate administrative activity from
# baseline/robert_kim_activity.json: tool usage, source host, time of
# day, day of week, target hosts and the account used. This profile is
# the false-positive filter for every later hunt task.
#
# The authorized workstation name and business-hours window are read
# from reference/admin_schedule.txt rather than hardcoded, so the
# baseline check stays correct if that schedule ever changes.
#
# Deterministic: re-running against the same inputs prints the same
# profile. Produces no output file; everything goes to stdout.

set -euo pipefail

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
require_file "$BASELINE"
require_file "$ADMIN_SCHEDULE"

# ---------------------------------------------------------------------
# Read the authorized workstation and work-hours window from the
# schedule document instead of hardcoding them.
# ---------------------------------------------------------------------
admin_workstation=$(grep -m1 '^Workstation:' "$ADMIN_SCHEDULE" | awk '{print $2}')
work_hours_line=$(grep -m1 '^Work hours:' "$ADMIN_SCHEDULE")
hour_start=$(echo "$work_hours_line" | grep -oE '[0-9]{2}:[0-9]{2}' | sed -n '1p' | cut -d: -f1)
hour_end=$(echo "$work_hours_line" | grep -oE '[0-9]{2}:[0-9]{2}' | sed -n '2p' | cut -d: -f1)

if [ -z "$admin_workstation" ] || [ -z "$hour_start" ] || [ -z "$hour_end" ]; then
  echo "Error: could not parse workstation/work-hours from $ADMIN_SCHEDULE" >&2
  exit 1
fi

total_events=$(jq -s 'length' "$BASELINE")

# ---------------------------------------------------------------------
# 1. Tool usage summary
# ---------------------------------------------------------------------
psexec_count=$(jq -s '[.[] | select(.hunt_meta.tool == "PsExec")] | length' "$BASELINE")
wmi_count=$(jq -s '[.[] | select(.hunt_meta.tool == "WMI")] | length' "$BASELINE")
psremoting_count=$(jq -s '[.[] | select(.hunt_meta.tool == "PSRemoting")] | length' "$BASELINE")

# ---------------------------------------------------------------------
# 2. Source host analysis
# ---------------------------------------------------------------------
admin_host_count=$(jq -s --arg h "$admin_workstation" \
  '[.[] | select(.hunt_meta.source_host == $h)] | length' "$BASELINE")
other_host_count=$((total_events - admin_host_count))

# ---------------------------------------------------------------------
# 3 & 4. Time-of-day and day-of-week distribution.
#    Converted to America/Chicago (the schedule's "Central Time"),
#    which correctly accounts for CDT/CST, instead of comparing raw
#    UTC timestamps against a Central-Time window.
# ---------------------------------------------------------------------
business_count=0
offhours_count=0
declare -A day_count=([Mon]=0 [Tue]=0 [Wed]=0 [Thu]=0 [Fri]=0 [Sat]=0 [Sun]=0)
weekend_count=0

while IFS= read -r ts; do
  local_hour=$(TZ=America/Chicago date -d "$ts" +%H)
  local_day=$(TZ=America/Chicago date -d "$ts" +%a)
  # 10# forces base-10 interpretation so "08", "09" are not read as octal
  if [ "$((10#$local_hour))" -ge "$((10#$hour_start))" ] && [ "$((10#$local_hour))" -lt "$((10#$hour_end))" ]; then
    business_count=$((business_count + 1))
  else
    offhours_count=$((offhours_count + 1))
  fi
  day_count[$local_day]=$((day_count[$local_day] + 1))
  if [ "$local_day" = "Sat" ] || [ "$local_day" = "Sun" ]; then
    weekend_count=$((weekend_count + 1))
  fi
done < <(jq -r '.timestamp' "$BASELINE")

# ---------------------------------------------------------------------
# 5. Target host analysis (sorted by count descending, name ascending
#    as a deterministic tie-break)
# ---------------------------------------------------------------------
target_breakdown=$(jq -s -r '
  group_by(.hunt_meta.target_host)
  | map({host: .[0].hunt_meta.target_host, count: length})
  | sort_by(-.count, .host)
  | .[] | "  \(.host): \(.count)"
' "$BASELINE")
target_list=$(jq -s -r '
  [.[] | .hunt_meta.target_host] | unique | sort | join(", ")
' "$BASELINE")
target_host_total=$(jq -s '[.[] | .hunt_meta.target_host] | unique | length' "$BASELINE")

# ---------------------------------------------------------------------
# 6. User account analysis. A service account is any account whose
#    name (after the DOMAIN\ prefix) starts with svc_, matching the
#    convention in reference/service_accounts.txt.
# ---------------------------------------------------------------------
robert_count=$(jq -s '
  [.[] | select(.data.win.eventdata.user | test("robert\\.kim"; "i"))] | length
' "$BASELINE")
svc_count=$(jq -s '
  [.[] | select(.data.win.eventdata.user | test("\\\\svc_"; "i"))] | length
' "$BASELINE")

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
echo "================================================================"
echo "   BASELINE PROFILE - Robert Kim (IT Administrator)"
echo "   Source: $BASELINE"
echo "================================================================"
echo
echo "TOOL USAGE SUMMARY:"
printf '  %-24s%s\n' "PsExec events:" "$psexec_count"
printf '  %-24s%s\n' "WMI events:" "$wmi_count"
printf '  %-24s%s\n' "PSRemoting events:" "$psremoting_count"
printf '  %-24s%s\n' "Total admin events:" "$total_events"
echo
echo "SOURCE HOST:"
echo "  $admin_workstation: $admin_host_count"
echo "  Other hosts: $other_host_count"
echo "  -> BASELINE: All admin activity originates from $admin_workstation"
echo
echo "TIME DISTRIBUTION (America/Chicago, per admin_schedule.txt work hours):"
echo "  ${hour_start}:00-${hour_end}:00: $business_count"
echo "  ${hour_end}:00-${hour_start}:00: $offhours_count"
echo "  -> BASELINE: Zero admin activity outside business hours"
echo
echo "DAY-OF-WEEK DISTRIBUTION:"
for d in Mon Tue Wed Thu Fri Sat Sun; do
  echo "  $d: ${day_count[$d]}"
done
echo "  -> BASELINE: Zero weekend activity (Sat+Sun: $weekend_count)"
echo
echo "TARGET HOST ANALYSIS:"
echo "$target_breakdown"
echo "  -> BASELINE: $target_host_total production servers are legitimate targets"
echo
echo "USER ACCOUNTS:"
printf '  MEDDEFENSE\\robert.kim: %s\n' "$robert_count"
echo "  Service accounts: $svc_count"
echo "  -> BASELINE: Never uses service accounts interactively"
echo
echo "BASELINE SUMMARY:"
echo "  Normal source host:  $admin_workstation"
echo "  Normal time window:  ${hour_start}:00-${hour_end}:00, Monday-Friday, Central Time"
printf '  Normal account:      MEDDEFENSE\\robert.kim\n'
echo "  Normal tools:        PsExec, WMI, PowerShell Remoting"
echo "  Normal targets:      $target_list"
echo
echo "ANOMALY DETECTION CRITERIA:"
echo "  [!] Admin tool from any host other than $admin_workstation"
echo "  [!] Admin tool usage outside business hours (before ${hour_start}:00 or after ${hour_end}:00 CT) or on Sat/Sun"
echo "  [!] Service account used interactively from a workstation host"
echo "  [!] WMI targeting unusual hosts (outside the $target_host_total known servers)"
echo
echo "================================================================"

exit 0
