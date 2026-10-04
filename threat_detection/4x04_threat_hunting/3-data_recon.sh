#!/bin/bash
# 3-data_recon.sh
#
# Data Reconnaissance: profiles the complete 14-day SIEM export before any
# hunt query is run. Answers "what does the data terrain actually look
# like" - time range, volume, event types, source hosts, severity, hourly
# pattern - and checks which hunt hypotheses (H1-H5) can even be tested
# against the data that is actually present.
#
# Reads only the files under siem_export/ (read-only). Produces no output
# file; everything is printed to stdout. Deterministic: re-running against
# the same inputs always prints the same report.

set -euo pipefail

ALERTS="siem_export/wazuh_alerts_14d.json"
SYSMON="siem_export/wazuh_raw_sysmon_14d.json"

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

# ---------------------------------------------------------------------
# Both files are newline-delimited JSON (one Wazuh alert object per
# line). The "complete SIEM export" is the two files combined.
# ---------------------------------------------------------------------
combined() {
  cat "$ALERTS" "$SYSMON"
}

# ---------------------------------------------------------------------
# 1. Dataset metadata
# ---------------------------------------------------------------------
total_events=$(combined | wc -l | tr -d ' ')
first_event=$(combined | jq -r '.timestamp' | sort | sed -n '1p')
last_event=$(combined | jq -r '.timestamp' | sort | sed -n '$p')

first_epoch=$(date -u -d "$first_event" +%s)
last_epoch=$(date -u -d "$last_event" +%s)
diff_sec=$((last_epoch - first_epoch))
duration_days=$((diff_sec / 86400))
duration_rem_hours=$(((diff_sec % 86400) / 3600))

# ---------------------------------------------------------------------
# 2. Event type distribution: top 10 by count, keyed on rule.id +
#    rule.description (the id disambiguates descriptions that repeat
#    across rule families).
# ---------------------------------------------------------------------
top_event_types=$(combined | jq -r '"\(.rule.id)\t\(.rule.description)"' \
  | sort | uniq -c | sort -rn | head -10 \
  | awk '{count=$1; $1=""; sub(/^ /,""); split($0,a,"\t"); printf "  %-7s%-8s%s\n", count, a[1], a[2]}')

# ---------------------------------------------------------------------
# 3. Source host distribution: events per agent, all hosts, sorted by
#    count descending (deterministic tie-break: hostname ascending).
# ---------------------------------------------------------------------
host_distribution=$(combined | jq -r '.agent.name' | sort | uniq -c \
  | sort -k1,1rn -k2,2 \
  | awk '{printf "  %-16s%s\n", $2":", $1}')

# ---------------------------------------------------------------------
# 4. Severity distribution: events by rule.level, ascending by level.
# ---------------------------------------------------------------------
severity_distribution=$(combined | jq -r '.rule.level' | sort -n | uniq -c \
  | awk '{printf "  Level %-10s%s\n", $2":", $1}')

# ---------------------------------------------------------------------
# 5. Hourly distribution: 24-hour histogram. Timestamps carry an
#    explicit "+00:00" offset, so the hour substring is UTC already -
#    no timezone conversion needed (unlike the admin-schedule baseline,
#    this dataset's hours are not being compared to a stated local
#    business-hours window).
# ---------------------------------------------------------------------
declare -A hour_count
for h in $(seq -w 0 23); do hour_count[$h]=0; done
while IFS=$'\t' read -r hour cnt; do
  hour_count[$hour]=$cnt
done < <(combined | jq -r '.timestamp[11:13]' | sort | uniq -c | awk '{printf "%s\t%s\n",$2,$1}')

# ---------------------------------------------------------------------
# 6. Hypothesis coverage matrix: does the export actually contain the
#    event types each hunt hypothesis depends on? OBSERVED by checking
#    for the specific process image / event pattern each hypothesis
#    needs, not merely by assuming it's there.
# ---------------------------------------------------------------------
has_evidence() {
  combined | jq -s -e "any(.[]; $1)" > /dev/null 2>&1
}

h1_ok="NOT COVERED"
has_evidence '(.data.win.eventdata.image? // "" | test("psexec";"i"))' && h1_ok="OK"

h2_ok="NOT COVERED"
has_evidence '(.rule.description? // "" | test("process accessed";"i")) or ((.data.win.eventdata.targetImage? // "") | test("lsass";"i"))' && h2_ok="OK"

h3_ok="NOT COVERED"
has_evidence '(.data.win.eventdata.image? // "" | test("wmic|wmiprfvse";"i"))' && h3_ok="OK"

h4_ok="NOT COVERED"
has_evidence '(.data.win.eventdata.image? // "" | test("wsmprovhost";"i"))' && h4_ok="OK"

h5_ok="NOT COVERED"
has_evidence '((.data.win.eventdata.targetUserName? // "") | test("svc_";"i")) or ((.data.win.eventdata.user? // "") | test("svc_";"i"))' && h5_ok="OK"

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
echo "================================================================"
echo "   DATA RECONNAISSANCE - MedDefense SIEM Export"
echo "================================================================"
echo
echo "DATASET METADATA:"
printf '  %-16s%s\n' "Total events:" "$total_events"
printf '  %-16s%s to %s\n' "Time range:" "$first_event" "$last_event"
printf '  %-16s%s days, %sh\n' "Duration:" "$duration_days" "$duration_rem_hours"
printf '  %-16s%s\n' "Format:" "JSON Lines (newline-delimited JSON), 2 files"
echo
echo "TOP 10 EVENT TYPES (count, rule ID, description):"
echo "$top_event_types"
echo
echo "SOURCE HOST DISTRIBUTION (events per agent):"
echo "$host_distribution"
echo
echo "SEVERITY DISTRIBUTION (rule.level):"
echo "$severity_distribution"
echo
echo "HOURLY DISTRIBUTION (24-hour histogram, UTC):"
for h in $(seq -w 0 23); do
  printf '  %s:00  %s\n' "$h" "${hour_count[$h]}"
done
echo
echo "HYPOTHESIS COVERAGE MATRIX:"
printf '  %-19s%s\n' "H1 (PsExec):" "[$h1_ok]"
printf '  %-19s%s\n' "H2 (LSASS):" "[$h2_ok]"
printf '  %-19s%s\n' "H3 (WMI):" "[$h3_ok]"
printf '  %-19s%s\n' "H4 (PSRemoting):" "[$h4_ok]"
printf '  %-19s%s\n' "H5 (Svc Accounts):" "[$h5_ok]"
echo
echo "================================================================"

exit 0
