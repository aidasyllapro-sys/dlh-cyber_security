#!/bin/bash
# 12-gap_analysis.sh
#
# Detection Gap Analysis: for each technique the Stage 4 hunt proved
# happened (Tasks 4, 6, 9, 10) without triggering an automated alert,
# documents the hunt finding, classifies why existing detection missed
# it, names the required data source, specifies the detection logic
# needed, and prioritizes remediation by risk.
#
# This script is documentary: it does not re-parse the SIEM exports.
# The findings below restate what the earlier hunt scripts already
# proved against the real data (see 4-hunt_psexec.sh,
# 6-hunt_credentials.sh, 9-hunt_svcaccount.sh,
# 10-evidence_correlation.sh). Produces no output file; everything is
# printed to stdout. Deterministic: always prints the same report.

set -euo pipefail

print_gap() {
  local num="$1" technique="$2" finding="$3" why="$4" source="$5" rule="$6" prio="$7"
  echo "GAP ${num}: ${technique}"
  printf '  Hunt Finding: %s\n' "$finding"
  printf '  Why Missed: %s\n' "$why"
  printf '  Data Source: %s\n' "$source"
  printf '  Required Rule: %s\n' "$rule"
  printf '  Priority: %s\n' "$prio"
  echo
}

echo "================================================================"
echo "   DETECTION GAP ANALYSIS - Stage 4 Techniques"
echo "================================================================"
echo

# ---------------------------------------------------------------------
# Gaps are printed P1 first, then P2, so the list is already
# prioritized by risk. Each one restates an actual hunt finding (never
# an invented scenario).
# ---------------------------------------------------------------------

print_gap 1 "T1021.002 PsExec Lateral Movement" \
  "PsExec-pattern remote execution from WS-RECV-03, a non-admin workstation, against SRV-HEALTH-DB/SRV-INS-DB (see 4-hunt_psexec.sh)." \
  "Missing rule - Sysmon Event 1 already logs the PsExec service creation and command line; no correlation rule existed to flag a source host outside the admin workstation allowlist." \
  "Sysmon Event 1 (Process Creation)" \
  "alert on PsExec (psexesvc.exe / commandLine matching psexec) where source host != WS-ADMIN-01 (or any documented admin host) or event occurs outside the documented maintenance window" \
  "P1"

print_gap 2 "T1003.001 LSASS Credential Access" \
  "debug_tool.exe (non-system process, non-SYSTEM user) accessed lsass.exe on WS-RECV-03 (see 6-hunt_credentials.sh)." \
  "Missing rule - Sysmon Event 10 already records every process that opens a handle to lsass.exe; no rule existed to flag a source image outside the AV/EDR allowlist." \
  "Sysmon Event 10 (ProcessAccess)" \
  "alert when TargetImage=lsass.exe and SourceImage is not in the allowlisted set of AV/EDR/OS processes under C:\\Windows\\System32, or SourceUser != NT AUTHORITY\\SYSTEM" \
  "P1"

print_gap 3 "T1047 WMI Remote Execution" \
  "Reconnaissance commands (dir, sc query, Get-ADUser) on SRV-HEALTH-DB, SRV-INS-DB and SRV-DC-01 all spawned with ParentImage=WmiPrvSE.exe (see 10-evidence_correlation.sh)." \
  "Missing rule - Sysmon Event 1 captures ParentImage on every process creation; no rule watched for WmiPrvSE.exe spawning shell or scripting processes outside known admin tooling." \
  "Sysmon Event 1 (Process Creation)" \
  "alert when ParentImage=WmiPrvSE.exe and Image is cmd.exe, powershell.exe or wmic.exe, unless the resulting command line matches an allowlisted admin/patch-management baseline" \
  "P1"

print_gap 4 "T1078.002 Service Account Misuse" \
  "svc_healthsync authenticated (Event 4624) from WS-RECV-03 to SRV-HEALTH-DB, SRV-INS-DB and SRV-DC-01 - hosts outside the account's documented authorization matrix (see 9-hunt_svcaccount.sh)." \
  "Data source missing - Event 4624 was logged correctly, but no automated check compared the logon's workstation/host against reference/service_accounts.txt; the allowlist existed only as a static document, not as live detection input." \
  "Windows Event 4624 (Logon) cross-referenced with the service-account authorization matrix" \
  "alert when a svc_* account's Event 4624 TargetHost or WorkstationName is not in that account's documented authorized-host list" \
  "P1"

print_gap 5 "T1021.006 PowerShell Remoting / Staging" \
  "Files staged via powershell.exe Copy-Item (wsmprovhost/PSRemoting session context) onto SRV-HEALTH-DB and SRV-INS-DB (see 10-evidence_correlation.sh)." \
  "Overly specific rule - the existing PowerShell-abuse rule only matches Invoke-Command/Enter-PSSession command lines; it does not cover Copy-Item file-transfer activity run inside the same remoting session." \
  "PowerShell logs (Event ID 4104, Script Block Logging) and Sysmon Event 1" \
  "alert on wsmprovhost.exe (or its child powershell.exe) executing Copy-Item with a UNC source path crossing hosts, not only on Invoke-Command/Enter-PSSession" \
  "P2"

print_gap 6 "T1550.002 NTLM / Pass-the-Hash-style Activity" \
  "Service-account logons used NTLM instead of the documented Kerberos-only requirement (see 9-hunt_svcaccount.sh)." \
  "Missing rule - Event 4624 already records AuthenticationPackageName; no rule existed to flag NTLM use by an account whose policy mandates Kerberos." \
  "Windows Event 4624 (Logon), field AuthenticationPackageName" \
  "alert when a svc_* account's AuthenticationPackageName=NTLM while its authorization matrix entry requires Kerberos-only authentication" \
  "P2"

echo "SUMMARY:"
echo "  The data was present."
echo "  The detection logic was missing."
echo "  Proactive hunting exposed the gap."
echo
echo "================================================================"

exit 0
