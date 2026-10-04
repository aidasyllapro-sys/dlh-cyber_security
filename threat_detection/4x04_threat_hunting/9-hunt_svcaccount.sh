#!/bin/bash
# 9-hunt_svcaccount.sh
#
# Hunt execution for H5: Service Account Abuse (T1078.002 Domain
# Accounts). Loads the service-account authorization matrix, extracts
# every authentication event for each listed service account (plus any
# undocumented svc_* account found in the data), classifies each event
# AUTHORIZED/UNAUTHORIZED against the matrix's own rules (wrong source
# host, interactive logon type, NTLM use), and correlates unauthorized
# usage with lateral-movement tooling (PsExec/WMI/PSRemoting) seen
# elsewhere in the hunt.
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
# 1. Load the authorization matrix: every "--- svc_xxx ---" block in
#    the reference document, and the host(s) named on its "Authorized
#    host:" line. Hosts are matched as SRV-/WS-style tokens so a
#    multi-host entry (svc_ad_replication: SRV-DC-01, SRV-DC-02) is
#    captured in full, and the IP address in parentheses is ignored.
# ---------------------------------------------------------------------
matrix_accounts=$(grep -oE '^--- svc_[a-zA-Z0-9_]+ ---' "$SVC_ACCOUNTS" | sed -E 's/^--- (svc_[a-zA-Z0-9_]+) ---$/\1/')

if [ -z "$matrix_accounts" ]; then
  echo "Error: no service accounts found in $SVC_ACCOUNTS" >&2
  exit 1
fi

declare -A authorized_hosts
for acct in $matrix_accounts; do
  hosts=$(sed -n "/--- ${acct} ---/,/^--- /p" "$SVC_ACCOUNTS" \
    | grep -m1 '^  Authorized host:' \
    | grep -oE '[A-Z]+-[A-Z0-9-]+' | sort -u | paste -sd ',')
  authorized_hosts["$acct"]="$hosts"
done

# ---------------------------------------------------------------------
# Any svc_* account present in the data but NOT in the matrix is, per
# the matrix's own closing section, suspect on its own (undocumented
# persistence account). Add it to the account list with an empty
# authorized-host set, which the classifier below treats as
# automatically UNAUTHORIZED.
# ---------------------------------------------------------------------
data_accounts=$(combined | jq -r '
  select(.rule.id == "60106")
  | (.data.win.eventdata.targetUserName? // "")
  | select(test("^svc_"))
' | sort -u)

all_accounts="$matrix_accounts"
undocumented_accounts=""
while IFS= read -r acct; do
  [ -z "$acct" ] && continue
  if [ -z "${authorized_hosts[$acct]+x}" ]; then
    authorized_hosts["$acct"]=""
    all_accounts="$all_accounts $acct"
    undocumented_accounts="$undocumented_accounts $acct"
  fi
done <<< "$data_accounts"

# ---------------------------------------------------------------------
# 2-4. For each account: extract its Windows Event 4624 (Successful
#    Logon, rule 60106) records, then classify AUTHORIZED/UNAUTHORIZED
#    against the matrix's three checkable rules:
#      RULE 1  source host (workstationName) must be the authorized
#              host (a workstation source is always a violation)
#      RULE 2  logon type must be 3 (Network) or 5 (Service); 2/10/11
#              (interactive) is a violation
#      RULE 3  authentication package must not be NTLM
#    An account with no matrix entry (undocumented) is UNAUTHORIZED on
#    every event, regardless of host/type/package.
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

declare -A total_count authorized_count unauthorized_count
declare -A unauthorized_lines
declare -a critical_accounts=()
grand_unauthorized=0

for acct in $all_accounts; do
  # join("\t") instead of @tsv: @tsv doubles backslashes and would
  # corrupt the "C:\Windows\..." style values this script also reads.
  records=$(combined | jq -r --arg acct "$acct" '
    select(.rule.id == "60106")
    | select(.data.win.eventdata.targetUserName? == $acct)
    | [
        .timestamp,
        .agent.name,
        (.data.win.eventdata.workstationName? // "UNKNOWN"),
        (.data.win.eventdata.logonType? // "UNKNOWN"),
        (.data.win.eventdata.authenticationPackageName? // "UNKNOWN")
      ] | join("\t")
  ' | sort)

  total=0
  authorized=0
  unauthorized=0
  lines=""

  auth_hosts="${authorized_hosts[$acct]}"

  while IFS=$'\t' read -r ts host wkstation logontype authpkg; do
    [ -z "$ts" ] && continue
    total=$((total + 1))

    bad=false
    if [ -z "$auth_hosts" ]; then
      bad=true  # undocumented account: no authorization exists at all
    else
      host_ok=false
      IFS=',' read -ra allowed <<< "$auth_hosts"
      for h in "${allowed[@]}"; do
        [ "$wkstation" = "$h" ] && host_ok=true
      done
      [ "$host_ok" = false ] && bad=true
      case "$logontype" in
        3|5) ;;
        *) bad=true ;;
      esac
      [ "$authpkg" = "NTLM" ] && bad=true
    fi

    if [ "$bad" = false ]; then
      authorized=$((authorized + 1))
    else
      unauthorized=$((unauthorized + 1))
      if [ "$host" = "$wkstation" ]; then
        display="$wkstation"
      else
        display="$host from $wkstation"
      fi
      lines="${lines}${ts}\t${display}\t${host}\t${wkstation}\n"
    fi
  done <<< "$records"

  total_count["$acct"]=$total
  authorized_count["$acct"]=$authorized
  unauthorized_count["$acct"]=$unauthorized
  unauthorized_lines["$acct"]="$lines"
  grand_unauthorized=$((grand_unauthorized + unauthorized))
done

# ---------------------------------------------------------------------
# 5. Correlate unauthorized usage with other hunt findings: for each
#    unauthorized event, check whether PsExec/WMI/PSRemoting activity
#    was also observed from the same source workstation against the
#    same target host (the same signal used in 4-hunt_psexec.sh and
#    6-hunt_credentials.sh).
# ---------------------------------------------------------------------
for acct in $all_accounts; do
  [ "${unauthorized_count[$acct]}" -eq 0 ] && continue
  correlated=false
  while IFS=$'\t' read -r ts display host wkstation; do
    [ -z "$ts" ] && continue
    if [ "$host" != "$wkstation" ] && correlate_tooling "$wkstation" "$host"; then
      correlated=true
    fi
  done <<< "$(printf '%b' "${unauthorized_lines[$acct]}")"
  [ "$correlated" = true ] && critical_accounts+=("$acct")
done

# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------
echo "================================================================"
echo "   HUNT EXECUTION - H5: Service Account Abuse"
echo "   Technique: T1078.002 Domain Accounts"
echo "================================================================"
echo

echo "SERVICE ACCOUNT AUTHORIZATION MATRIX:"
for acct in $matrix_accounts; do
  printf '  %s: Authorized on %s only\n' "$acct" "${authorized_hosts[$acct]}"
done
if [ -n "$undocumented_accounts" ]; then
  for acct in $undocumented_accounts; do
    printf '  %s: NOT IN AUTHORIZATION MATRIX (undocumented account)\n' "$acct"
  done
fi
echo

echo "AUTHENTICATION AUDIT:"
echo
for acct in $all_accounts; do
  echo "  ${acct}:"
  printf '    Total auth events: %s\n' "${total_count[$acct]}"
  printf '    Authorized: %s\n' "${authorized_count[$acct]}"
  printf '    UNAUTHORIZED: %s\n' "${unauthorized_count[$acct]}"
  if [ "${unauthorized_count[$acct]}" -gt 0 ]; then
    while IFS=$'\t' read -r ts display host wkstation; do
      [ -z "$ts" ] && continue
      printf '      [%s] %s\n' "$ts" "$display"
    done <<< "$(printf '%b' "${unauthorized_lines[$acct]}")"
  fi
  echo
done

echo "CORRELATION WITH OTHER HUNT FINDINGS:"
if [ "${#critical_accounts[@]}" -gt 0 ]; then
  for acct in "${critical_accounts[@]}"; do
    echo "  ${acct}: unauthorized workstation use correlates with PsExec/WMI/PSRemoting"
    echo "    lateral-movement activity from the same source host (see H1/H2 hunts)."
  done
else
  if [ "$grand_unauthorized" -gt 0 ]; then
    echo "  Unauthorized service-account use was found, but no correlated"
    echo "  PsExec/WMI/PSRemoting activity was observed from the same source."
  else
    echo "  No unauthorized service-account use found; nothing to correlate."
  fi
fi
echo

echo "FINDING:"
if [ "${#critical_accounts[@]}" -gt 0 ]; then
  echo "  Status: POSITIVE - CRITICAL CONFIDENCE"
  for acct in "${critical_accounts[@]}"; do
    echo "  ${acct} was used from a workstation and correlated with"
    echo "  lateral movement activity."
  done
elif [ "$grand_unauthorized" -gt 0 ]; then
  echo "  Status: POSITIVE - HIGH CONFIDENCE"
  echo "  Unauthorized service-account authentication was found, but without"
  echo "  corroborating lateral-movement tooling from the same source."
else
  echo "  Status: NEGATIVE"
  echo "  All service-account authentication matches the documented"
  echo "  authorization matrix."
fi
echo
echo "================================================================"

exit 0
