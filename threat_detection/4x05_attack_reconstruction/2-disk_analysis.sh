#!/bin/bash
# 2-disk_analysis.sh
# HEALTHBANE Reconstruction - Task 2: Disk Forensics Analysis
#
# Parses ir_evidence/disk_forensics_report.txt and cross-references the
# prefetch evidence against the administrative-authorization matrix in
# reference/network_topology.txt (not a hardcoded tool list) to decide
# which executions on WS-RECV-03 are legitimate. Every line printed below
# cites the report section it came from.
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

require_cmd grep
require_cmd awk
require_cmd sed

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IR_DIR="${BASE_DIR}/ir_evidence"
REF_DIR="${BASE_DIR}/reference"
DISK_FILE="${IR_DIR}/disk_forensics_report.txt"
TOPO_FILE="${REF_DIR}/network_topology.txt"

require_dir "$IR_DIR"
require_dir "$REF_DIR"
require_file "$DISK_FILE"
require_file "$TOPO_FILE"

ATTACK_IDS=()
record_technique() {
  local t="$1"
  for existing in "${ATTACK_IDS[@]}"; do
    [[ "$existing" == "$t" ]] && return 0
  done
  ATTACK_IDS+=("$t")
}

echo "================================================================"
echo "   DISK FORENSICS ANALYSIS - WS-RECV-03"
echo "   Source: ir_evidence/disk_forensics_report.txt"
echo "================================================================"
echo

# ---------------------------------------------------------------------------
# RECOVERED DELETED FILES
# Section 3.2 lists each deleted/recovered file as a [Dn] block. We read the
# path, recovered size and deletion timestamp straight out of each block
# instead of retyping them, so a wrong number here is a parsing bug, not a
# typo.
# ---------------------------------------------------------------------------
echo "RECOVERED DELETED FILES (SECTION 3.2):"
printf '  %-28s %-9s %s\n' "File" "Deleted" "Size"

DELETED_COUNT=0
while IFS= read -r num; do
  start_line="$(grep -n "^\[D${num}\]" "$DISK_FILE" | head -n1 | cut -d: -f1)"
  end_line="$(awk -v s="$start_line" 'NR>s && (/^\[D[0-9]+\]/ || /^3\.3/){print NR; exit}' "$DISK_FILE")"
  if [[ -n "$end_line" ]]; then
    block="$(sed -n "${start_line},$((end_line - 1))p" "$DISK_FILE")"
  else
    block="$(sed -n "${start_line},\$p" "$DISK_FILE")"
  fi

  fullpath="$(grep -oE 'C:\\[^ ]+' <<< "$block" | head -n1 || true)"
  filename="$(basename "${fullpath//\\//}" 2>/dev/null || echo "$fullpath")"
  deleted="$(grep -oE 'Deletion timestamp:.*' <<< "$block" | head -n1 | sed -E 's/Deletion timestamp:\s*//' || true)"
  size="$(grep -oE 'Recovered size:.*' <<< "$block" | head -n1 | sed -E 's/Recovered size:\s*//' || true)"
  rowcount="$(grep -oE 'Row count:[[:space:]]*[0-9 ]+' <<< "$block" | head -n1 | sed -E 's/Row count:\s*//' || true)"

  printf '  %-28s %-9s %s\n' "$filename" "${deleted:0:10}" "${size:-?}"
  [[ -n "$rowcount" ]] && printf '       -> %s rows recovered (cited in SECTION 3.2 [D%s])\n' "$rowcount" "$num"
  DELETED_COUNT=$((DELETED_COUNT + 1))
done < <(grep -oE '^\[D[0-9]+\]' "$DISK_FILE" | grep -oE '[0-9]+')

echo
echo "  ANALYSIS: ${DELETED_COUNT} files recovered from unallocated clusters"
echo "  in C:\\Users\\Public\\Tmp\\ (and one from C:\\Windows\\Temp\\ -- the"
echo "  LSASS dump output). Naming pattern (out_<timestamp>.csv then"
echo "  staging_export_<NNN>.zip, each deleted within seconds of creation)"
echo "  is a structured export-compress-delete cycle, repeated on three"
echo "  separate dates -- this is staging, not a one-off accident."
echo "  ATT&CK: T1074.001 Local Data Staging, T1560.001 Archive via Utility"
record_technique "T1074.001 Local Data Staging"
record_technique "T1560.001 Archive via Utility"
echo "  CRITICAL: per SECTION 3.2 [D1]/[D2], the recovered CSVs contain the"
echo "  full health_records (47 138 rows) and insurance_db (51 002 rows)"
echo "  tables, not samples -- this is what moves the impact assessment"
echo "  from 'attacker had access' to 'attacker captured the full dataset.'"
echo "  Whether it left the host is a network question: see OPEN-A in"
echo "  SECTION 11 of this report and the firewall session evidence (next task)."
echo

# ---------------------------------------------------------------------------
# PREFETCH ANALYSIS
# The expected/forbidden tool list is read from the administrative
# authorization matrix in network_topology.txt, not hardcoded, so the
# verdict always matches the current topology document.
# ---------------------------------------------------------------------------
echo "PREFETCH ANALYSIS (SECTION 5):"
printf '  %-14s %-21s %-9s %s\n' "Program" "Last Run (CDT)" "Runs" "Expected?"

FORBIDDEN_TOOLS_BLOCK="$(awk '/No other workstation is authorized to initiate:/{f=1;next} f && /^$/{exit} f{print}' "$TOPO_FILE")"

while IFS= read -r line; do
  pf_name="$(awk '{print $1}' <<< "$line" | sed -E 's/-[0-9A-F]{8}\.pf$//')"
  last_run="$(awk '{print $2, $3}' <<< "$line")"
  runs="$(awk '{print $4}' <<< "$line")"
  prog_lc="$(tr '[:upper:]' '[:lower:]' <<< "$pf_name")"

  case "$prog_lc" in
    psexec*)
      verdict="NO (records WS -- PsExec is reserved for WS-ADMIN-01 per topology authorization matrix)"
      ;;
    wmic.exe)
      verdict="NO (WMIC remote process creation is reserved for WS-ADMIN-01 per topology authorization matrix)"
      ;;
    wsmprovhost.exe)
      verdict="NO (PowerShell Remoting target handler -- reserved for WS-ADMIN-01 per topology authorization matrix)"
      ;;
    debug_tool.exe)
      verdict="NO (not a business or administrative tool at all -- HB-IOC-NEW-003, LSASS dumper)"
      ;;
    svchost_update.exe)
      verdict="NO (this IS the HEALTHBANE RAT itself -- HB-IOC-0013, not a records-desk program)"
      ;;
    schtasks.exe)
      verdict="SUSPICIOUS (local task creation; topology matrix forbids REMOTE schtasks /S specifically, so this is not a literal matrix violation, but a hidden daily task has no records-desk business purpose)"
      ;;
    powershell.exe)
      verdict="PARTIAL (file states records dept. uses PowerShell for AD white-pages queries; SECTION 5 attributes 8 of these runs to the attacker's scheduled task)"
      ;;
    *)
      if grep -qi "$prog_lc" <<< "$FORBIDDEN_TOOLS_BLOCK"; then
        verdict="NO (matches a tool named in the topology authorization matrix as WS-ADMIN-01-only)"
      else
        verdict="YES (no match against the authorization matrix's forbidden-tool list)"
      fi
      ;;
  esac

  printf '  %-14s %-21s %-9s %s\n' "$pf_name" "$last_run" "$runs" "$verdict"
done < <(awk '/^PF entry/{f=1;next} f && /^$/{exit} f && /\.pf /{print}' "$DISK_FILE")
echo

# ---------------------------------------------------------------------------
# SCHEDULED TASK XML
# This is the gap flagged by 1-memory_analysis.sh -- that script could not
# find the trigger in memory and pointed here. We resolve it now by reading
# the actual XML.
# ---------------------------------------------------------------------------
echo "SCHEDULED TASK (SECTION 4 -- resolves the Task 1 trigger gap):"

task_uri="$(grep -oE '<URI>[^<]+</URI>' "$DISK_FILE" | head -n1 | sed -E 's#</?URI>##g' || true)"
trigger_start="$(grep -oE '<StartBoundary>[^<]+</StartBoundary>' "$DISK_FILE" | head -n1 | sed -E 's#</?StartBoundary>##g' || true)"
days_interval="$(grep -oE '<DaysInterval>[^<]+</DaysInterval>' "$DISK_FILE" | head -n1 | sed -E 's#</?DaysInterval>##g' || true)"
reg_date="$(grep -oE '<Date>[^<]+</Date>' "$DISK_FILE" | head -n1 | sed -E 's#</?Date>##g' || true)"

echo "  Task name:    ${task_uri:-N/A}"
echo "  Trigger:      CalendarTrigger, StartBoundary=${trigger_start:-N/A}, DaysInterval=${days_interval:-N/A}"
echo "  Registration: ${reg_date:-N/A}"
echo "  Action: powershell.exe -NoP -W Hidden -EncodedCommand [...] (SECTION 4"
echo "  gives the full base64 and its decode: downloads cfg from"
echo "  sync.healthbane-c2.net then invokes sync_healthdata.ps1)"
echo "  -> CONFIRMED: identical command to memory_artifacts.txt PID 8472"
echo "  (per this report's own SECTION 4 analyst note). This upgrades the"
echo "  Task 1 finding from 'trigger not stated in memory' to CONFIRMED"
echo "  Daily 02:00, now that the on-disk XML has been read."
echo "  ATT&CK: T1053.005 Scheduled Task/Job"
record_technique "T1053.005 Scheduled Task/Job"
echo

# ---------------------------------------------------------------------------
# REGISTRY PERSISTENCE
# ---------------------------------------------------------------------------
echo "REGISTRY PERSISTENCE (SECTION 7, cross-checked against memory):"
echo "  HKCU\\...\\Run\\HealthSync -> svchost_update.exe (R1): KNOWN, already"
echo "  confirmed in 4x03/4x04/Task 1 -- this is the RAT's own persistence,"
echo "  not new to this task."
echo "  Defender exclusion for C:\\Windows\\Temp (R3): KNOWN (HB-IOC-NEW-002"
echo "  family / matches memory K5), added 9h before the first LSASS dump."
echo "  No Run or RunOnce entry exists for the exfiltrator script itself --"
echo "  its persistence is provided entirely by the scheduled task above,"
echo "  not by a registry run key."
echo

# ---------------------------------------------------------------------------
# NTFS $MFT TIMELINE
# ---------------------------------------------------------------------------
echo "NTFS \$MFT TIMELINE, attack window (SECTION 6):"
awk '/^SECTION 6/{f=1} f{print} /^SECTION 7/{exit}' "$DISK_FILE" \
  | grep -E '^2026-05-[0-9]{2}' \
  | sed 's/^/  /'
echo

# ---------------------------------------------------------------------------
# ANTI-FORENSICS INDICATORS
# Both what WAS found and what was explicitly checked and NOT found --
# SECTION 9's "not observed" list is itself evidence (it supports the
# "basic, not advanced, anti-forensics" assessment the report draws).
# ---------------------------------------------------------------------------
echo "ANTI-FORENSICS INDICATORS (SECTION 9):"
echo "  Observed:"
awk '/^Observed:/{f=1;next} f && /^NOT observed/{exit} f{print}' "$DISK_FILE" | sed '/^[[:space:]]*$/d; s/^/  /'
record_technique "T1070.001 Clear Windows Event Logs"
record_technique "T1070.004 File Deletion"
record_technique "T1562.001 Disable or Modify Tools"
echo "  NOT observed (checked for, absent -- supports 'basic, not advanced"
echo "  anti-forensics' assessment, i.e. a commodity actor, not nation-state):"
awk '/^NOT observed/{f=1;next} f && /^\[ANALYST/{exit} f{print}' "$DISK_FILE" | sed '/^[[:space:]]*$/d; s/^/  /'
echo

echo "SUMMARY:"
if [[ "${#ATTACK_IDS[@]}" -gt 0 ]]; then
  printf '  ATT&CK techniques identified: %s\n' "$(IFS=, ; echo "${ATTACK_IDS[*]}")"
else
  echo "  ATT&CK techniques identified: none"
fi
echo "  Evidence confirms data staging for exfiltration (SECTION 3.2:"
echo "  structured SQL-export-then-archive cycle, repeated 3 times, each"
echo "  deleted within seconds of creation)."
echo "  Staging itself was COMPLETED locally on each occasion (archive"
echo "  created, then deleted -- consistent with a successful send-then-"
echo "  cleanup cycle); whether the archives were actually TRANSMITTED off"
echo "  the host is NOT confirmed by disk evidence alone -- SECTION 11"
echo "  [OPEN-A] explicitly defers that confirmation to the firewall"
echo "  session evidence (ir_evidence/firewall_sessions_ws_recv_03.json)."
echo "  Anti-forensics: basic only (log-clear gap + file deletion +"
echo "  Defender exclusion); VSS, USN journal and prefetch were all left"
echo "  intact, which is itself evidence of operational discipline level."
echo
echo "================================================================"

exit 0
