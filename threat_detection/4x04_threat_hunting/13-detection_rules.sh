#!/bin/bash
# 13-detection_rules.sh
#
# Detection Engineering: translates the gaps identified in
# 12-gap_analysis.sh into draft detection rules - four Wazuh-style
# host rules plus one network-level rule - so the techniques the hunt
# uncovered (Tasks 4, 5, 6, 9, 10) trigger an automated alert next
# time. Closes the loop of the threat-hunting cycle: hunt -> find ->
# detect -> hunt again.
#
# This project is self-contained: these are local rule drafts and
# documentation, not a live SIEM deployment. Produces no output file;
# everything is printed to stdout. Deterministic: always prints the
# same report.

set -euo pipefail

print_rule() {
  local id="$1" title="$2" behavior="$3" evidence="$4" fprate="$5" baseline="$6"
  echo "[Rule ${id}] ${title}"
  printf '  Behavior: %s\n' "$behavior"
  printf '  Evidence: %s\n' "$evidence"
  printf '  FP Rate: %s\n' "$fprate"
  printf '  Baseline: %s\n' "$baseline"
  echo
}

echo "================================================================"
echo "   DETECTION ENGINEERING - Hunt-Derived Rules"
echo "================================================================"
echo

echo "=== WAZUH-STYLE RULE DRAFTS ==="
echo

print_rule 100100 "PsExec from Non-Admin Workstation" \
  "PsExec execution from non-admin workstation" \
  "Hunt Task 4" \
  "VERY LOW" \
  "compare source host (agent.name) against the documented admin-workstation allowlist (e.g. WS-ADMIN-01); alert when source is outside it or the event falls outside the documented maintenance window"

print_rule 100101 "LSASS Memory Access from Non-System Process" \
  "Suspicious LSASS access" \
  "Hunt Task 6" \
  "LOW" \
  "compare SourceImage against the C:\\Windows\\System32\\ AV/EDR allowlist and SourceUser against NT AUTHORITY\\SYSTEM; alert on any value outside that baseline"

print_rule 100102 "Service Account Interactive Logon from Workstation" \
  "service account used from workstation" \
  "Hunt Task 9" \
  "VERY LOW" \
  "compare targetUserName/workstationName (Event 4624) against the service-account authorization matrix (reference/service_accounts.txt); alert on a host, logon type or auth package outside the documented entry"

print_rule 100103 "WMI Remote Child Process Anomaly" \
  "wmiprvse.exe spawning cmd.exe or powershell.exe" \
  "Hunt Task 5" \
  "MEDIUM" \
  "compare the resulting command line against the allowlisted admin/patch-management baseline of known WmiPrvSE.exe children; alert on any command line outside that baseline"

echo "=== NETWORK RULE DRAFTS ==="
echo

print_rule 9000030 "SMB Lateral Movement - PsExec Service Installation" \
  "PsExec service installation pattern" \
  "Hunt Task 4" \
  "LOW" \
  "compare the source/destination host pair and service name (PSEXESVC) against the documented admin maintenance baseline; alert on any pair outside it"

echo "=== DETECTION POSTURE UPDATE ==="
echo "  Before hunt: 55% observed coverage"
echo "  After hunt: approximately 80% coverage"
echo "  Improved ATT&CK coverage:"
echo "    T1021.002 (PsExec/SMB Admin Shares) - now covered (Rules 100100, 9000030)"
echo "    T1003.001 (LSASS Memory) - now covered (Rule 100101)"
echo "    T1078.002 (Domain/Service Accounts) - now covered (Rule 100102)"
echo "    T1047 (Windows Management Instrumentation) - now covered (Rule 100103)"
echo

echo "================================================================"

exit 0
