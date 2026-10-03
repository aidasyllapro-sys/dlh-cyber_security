#!/bin/bash
# 0-hunt_brief.sh
#
# Builds the Stage 4 threat hunt brief:
#   - summarizes the HC3 Stage 4 TTP profile from the advisory
#   - cross-references the post-4x03 ATT&CK coverage map to show which
#     Stage 4 techniques are NOT COVERED (the hunting target)
#   - states scope, data sources, time window and priority ranking
#
# Reads only the files under reference/ (read-only). Produces no output
# file; everything is printed to stdout. Deterministic: re-running against
# the same inputs always prints the same brief.

set -euo pipefail

ADVISORY="reference/hc3_advisory_004.txt"
ATTACK_MAP="reference/4x03_attack_mapping.json"
ADMIN_SCHEDULE="reference/admin_schedule.txt"
SVC_ACCOUNTS="reference/service_accounts.txt"
NET_TOPOLOGY="reference/network_topology.txt"
SIEM_ALERTS="siem_export/wazuh_alerts_14d.json"
SIEM_SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
BASELINE="baseline/robert_kim_activity.json"

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
require_file "$ADVISORY"
require_file "$ATTACK_MAP"
require_file "$ADMIN_SCHEDULE"
require_file "$SVC_ACCOUNTS"
require_file "$NET_TOPOLOGY"
require_file "$SIEM_ALERTS"
require_file "$SIEM_SYSMON"
require_file "$BASELINE"

# ---------------------------------------------------------------------
# 1. Stage 4 TTP summary, derived from the advisory text.
#    Each bullet is only printed if its corresponding evidence keyword
#    is actually present in the advisory, so the brief stays accurate
#    if the advisory text changes.
# ---------------------------------------------------------------------
advisory_has() {
  grep -qiE -- "$1" "$ADVISORY"
}

declare -a ttp_lines=()
advisory_has 'PsExec' \
  && ttp_lines+=("PsExec for remote command execution on servers")
advisory_has 'WMI|wmic\.exe' \
  && ttp_lines+=("WMI for remote process creation and enumeration")
advisory_has 'PSRemoting|PowerShell Remoting|WinRM' \
  && ttp_lines+=("PowerShell Remoting for interactive access and staging")
advisory_has 'LSASS' \
  && ttp_lines+=("Credential dumping via LSASS memory access")
advisory_has 'service account' \
  && ttp_lines+=("Service account abuse for lateral authentication")
advisory_has 'off-hours|01:00 and 0[4-5]:00' \
  && ttp_lines+=("Off-hours operations to avoid detection")

# ---------------------------------------------------------------------
# 2. ATT&CK coverage gap, read from the 4x03 coverage map.
#    Technique IDs correspond to the advisory TTPs above (PsExec, WMI,
#    PSRemoting, LSASS, service-account abuse). Technique names follow
#    MITRE ATT&CK naming; verify against attack.mitre.org if the
#    ATT&CK version in use differs from the one cited in the map
#    (the map declares ATT&CK version 14).
# ---------------------------------------------------------------------
declare -a gap_ids=("T1021.002" "T1047" "T1021.006" "T1003.001" "T1078.002")
declare -A gap_names=(
  ["T1021.002"]="SMB/Windows Admin Shares"
  ["T1047"]="WMI"
  ["T1021.006"]="Windows Remote Management"
  ["T1003.001"]="LSASS Memory"
  ["T1078.002"]="Domain Accounts"
)

color_to_state() {
  case "$1" in
    "#c40000") echo "OBSERVED" ;;
    "#ffcf00") echo "INFERRED" ;;
    "#8a8a8a") echo "NOT COVERED" ;;
    *) echo "UNKNOWN" ;;
  esac
}

observed=$(jq -r '.technique_count_summary.observed' "$ATTACK_MAP")
total=$(jq -r '.technique_count_summary.total_in_threat_model' "$ATTACK_MAP")
pct=$(jq -r '.technique_count_summary.percent_observed' "$ATTACK_MAP")

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
echo "================================================================"
echo "   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)"
echo "   Classification: TLP:AMBER"
echo "================================================================"
echo
echo "HC3 ADVISORY SUMMARY:"
echo "  Stage 4 TTPs:"
for line in "${ttp_lines[@]}"; do
  echo "    [*] $line"
done
echo
echo "ATT&CK COVERAGE GAP ANALYSIS:"
echo "  Current coverage: ${observed}/${total} techniques (${pct}%)"
echo "  Stage 4 techniques in gap:"
for id in "${gap_ids[@]}"; do
  color=$(jq -r --arg id "$id" '.techniques[] | select(.techniqueID == $id) | .color' "$ATTACK_MAP")
  state=$(color_to_state "$color")
  printf '    %-11s%-30s%s\n' "$id" "${gap_names[$id]}" "$state"
done
echo
echo "HUNT PRIORITY RANKING:"
# Ranking rationale (analyst judgment, not derived mechanically from the
# map): P1 PsExec is ranked first because it gives the clearest baseline
# deviation signal (source host is a hard boolean check against
# admin_schedule.txt). P2 LSASS is ranked next because credential access
# is the prerequisite that enables every later-stage technique. P3-P5
# follow the advisory's typical operational order (WMI recon, then
# PSRemoting staging, then the service-account abuse that the earlier
# steps depend on).
echo "  P1: T1021.002 PsExec"
echo "  P2: T1003.001 LSASS"
echo "  P3: T1047 WMI"
echo "  P4: T1021.006 PSRemoting"
echo "  P5: T1078.002 Domain Accounts"
echo
echo "DATA SOURCES:"
echo "  Primary: $SIEM_ALERTS"
echo "  Secondary: $SIEM_SYSMON"
echo "  Baseline: $BASELINE"
echo "  Reference: admin_schedule.txt, service_accounts.txt, network_topology.txt"
echo
echo "TIME WINDOW: 14 days"
echo
echo "================================================================"

exit 0
