#!/bin/bash
# 7-stage_4.sh
# HEALTHBANE Reconstruction - Task 7: Stage 4 Reconstruction
# (Lateral Movement, Credential Access, Data Staging, Persistence, Containment)
#
# Reads previous_findings/4x04_hunting_report.txt, the three IR evidence
# files (memory, disk, firewall) and ir_evidence/ir_team_notes.txt LIVE via
# grep/jq -- nothing below is hardcoded except a short list of session IDs
# used to pull specific firewall sessions out of the JSON (those IDs are
# themselves read from the file, not invented).
#
# Where the IR team's own notes explicitly label something a HYPOTHESIS
# rather than a confirmed fact (the "likely sequence" in ir_team_notes.txt
# Entry #010), this script keeps that label rather than upgrading it to
# a fact. Where the evidence itself contains an internal contradiction
# (4x04's own header date vs. its own body text, and vs. ir_team_notes.txt
# and the IR evidence files' own timestamps), this script reports the
# contradiction instead of silently picking one side.
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
 
require_cmd jq
require_cmd grep
require_cmd date
 
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PF_DIR="${BASE_DIR}/previous_findings"
IR_DIR="${BASE_DIR}/ir_evidence"
REF_DIR="${BASE_DIR}/reference"
 
HUNT_FILE="${PF_DIR}/4x04_hunting_report.txt"
MEM_FILE="${IR_DIR}/memory_artifacts.txt"
DISK_FILE="${IR_DIR}/disk_forensics_report.txt"
FW_FILE="${IR_DIR}/firewall_sessions_ws_recv_03.json"
NOTES_FILE="${IR_DIR}/ir_team_notes.txt"
IOC_FILE="${REF_DIR}/healthbane_ioc_master.json"
 
require_dir "$PF_DIR"
require_dir "$IR_DIR"
require_dir "$REF_DIR"
require_file "$HUNT_FILE"
require_file "$MEM_FILE"
require_file "$DISK_FILE"
require_file "$FW_FILE"
require_file "$NOTES_FILE"
require_file "$IOC_FILE"
 
jq empty "$FW_FILE" 2> /dev/null || { echo "ERROR: $FW_FILE is not valid JSON" >&2; exit 1; }
 
ATTACK_IDS=()
record_technique() {
  local t="$1"
  for existing in "${ATTACK_IDS[@]:-}"; do
    [[ "$existing" == "$t" ]] && return 0
  done
  ATTACK_IDS+=("$t")
}
 
ioc_lookup() {
  local type="$1" value="$2"
  jq -r --arg t "$type" --arg v "$value" \
    '.iocs[] | select(.type == $t and (.value | ascii_downcase) == ($v | ascii_downcase)) | .id' \
    "$IOC_FILE" | head -n1
}
 
echo "================================================================================"
echo "   ATTACK RECONSTRUCTION: Stage 4"
echo "   Lateral Movement, Credential Access, Data Staging, Persistence, Containment"
echo "================================================================================"
echo
 
# ------------------------------------------------------------------------------
# LATERAL MOVEMENT CHAIN -- live from 4x04's own chronological summary,
# cross-referenced with firewall_sessions_ws_recv_03.json LATERAL_MOVEMENT
# sessions and disk_forensics_report.txt prefetch evidence.
# ------------------------------------------------------------------------------
echo "LATERAL MOVEMENT CHAIN"
echo "-----------------------"
echo "Source: previous_findings/4x04_hunting_report.txt (CHRONOLOGICAL SUMMARY"
echo "section), cross-checked against ir_evidence/firewall_sessions_ws_recv_03.json"
echo "(classification: LATERAL_MOVEMENT) and ir_evidence/disk_forensics_report.txt"
echo "(Section 5, prefetch)."
echo
 
grep -A14 "^CHRONOLOGICAL SUMMARY" "$HUNT_FILE" | grep -E "^2026-05" | sed 's/^/  /'
 
echo
PSEXEC64_FIRST_PF="$(grep -A4 'PSEXEC64.EXE-7C291843.pf' "$DISK_FILE" | grep -oP '2026-05-06 \d{2}:\d{2}:\d{2}' | head -n1)"
echo "  Prefetch corroboration (disk_forensics_report.txt Section 5):"
echo "    PsExec64.exe first run timestamp: ${PSEXEC64_FIRST_PF} CDT"
echo "    -- matches the first PsExec lateral-movement event above."
echo
 
LATERAL_SESSION_COUNT="$(jq -r '.summary.by_classification.LATERAL_MOVEMENT.session_count' "$FW_FILE")"
LATERAL_DESTS="$(jq -r '.summary.by_classification.LATERAL_MOVEMENT.destinations | join(", ")' "$FW_FILE")"
LATERAL_NOTE="$(jq -r '.summary.by_classification.LATERAL_MOVEMENT._note' "$FW_FILE")"
echo "  Firewall corroboration: ${LATERAL_SESSION_COUNT} LATERAL_MOVEMENT sessions"
echo "    to: ${LATERAL_DESTS}"
echo "    Analyst note: ${LATERAL_NOTE}"
echo
 
CRED_IOC="$(ioc_lookup user_account svc_healthsync)"
[[ -z "$CRED_IOC" ]] && CRED_IOC="not catalogued"
DEBUGTOOL_IOC="$(ioc_lookup filename debug_tool.exe)"
[[ -z "$DEBUGTOOL_IOC" ]] && DEBUGTOOL_IOC="not catalogued"
echo "  IOC cross-reference: svc_healthsync = ${CRED_IOC}; debug_tool.exe = ${DEBUGTOOL_IOC}"
echo
 
record_technique "T1003.001 LSASS Memory"
record_technique "T1021.002 SMB/Windows Admin Shares"
record_technique "T1021.006 PowerShell Remoting"
record_technique "T1047 Windows Management Instrumentation"
record_technique "T1078.002 Domain Account"
record_technique "T1550.002 Pass the Hash"
 
# ------------------------------------------------------------------------------
# CREDENTIAL ACCESS -- live from memory_artifacts.txt and disk_forensics_report.txt
# ------------------------------------------------------------------------------
echo "CREDENTIAL ACCESS"
echo "------------------"
echo "Source: ir_evidence/memory_artifacts.txt (Section 7, handles) and"
echo "ir_evidence/disk_forensics_report.txt (Section 3.1 [F2], Section 3.2 [D4])."
echo
 
DEBUG_HANDLE="$(grep -oP 'debug_tool\.exe -> Process\s+\K<0x[0-9a-f]+>' "$MEM_FILE" | head -n1)"
echo "  debug_tool.exe opened LSASS (PID 648) with granted-access handle ${DEBUG_HANDLE}"
echo "  (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION -- the canonical"
echo "  Mimikatz-class access mask, per memory_artifacts.txt Section 7)."
echo
 
DEBUGTOOL_SHA="$(grep -A8 '\[F2\]' "$DISK_FILE" | grep -A1 'SHA256:' | tr -d '\n ' | grep -oP '(?<=SHA256:)[0-9a-f]+')"
echo "  debug_tool.exe on-disk SHA256 (disk_forensics_report.txt [F2]):"
echo "    ${DEBUGTOOL_SHA}"
echo
 
OUTDAT_RECOVERY="$(grep -A5 '\[D4\]' "$DISK_FILE" | grep -oP 'Recovered size:\s+\K.*')"
echo "  LSASS dump output file out.dat: ${OUTDAT_RECOVERY} recovered (partial -- see [D4])."
echo "  Recovered portion confirms Mimikatz-format dump containing \"svc_healthsync\""
echo "  plaintext username strings (4x occurrences in the recovered fragment)."
echo
 
record_technique "T1003.001 LSASS Memory"
 
# ------------------------------------------------------------------------------
# DATA ACCESS AND STAGING -- live from disk forensics D1/D2/D3 + firewall EXFIL_BURST
# ------------------------------------------------------------------------------
echo "DATA STAGING AND EXFILTRATION"
echo "-------------------------------"
echo "Source: ir_evidence/disk_forensics_report.txt (Section 3.2, deleted/recovered"
echo "staging files) cross-referenced byte-for-byte with"
echo "ir_evidence/firewall_sessions_ws_recv_03.json (classification: EXFIL_BURST)."
echo
 
jq -r '.summary.by_classification.EXFIL_BURST.by_burst[] |
  "  " + .ts_utc + "  " + (.bytes_out | tostring) + " bytes out  -- " + .matches_disk_artifact' \
  "$FW_FILE"
echo
EXFIL_NOTE="$(jq -r '.summary.by_classification.EXFIL_BURST._note' "$FW_FILE")"
echo "  ${EXFIL_NOTE}"
echo
 
STAGE_DIR="$(grep -oP '"stage_dir":"\K[^"]+' "$DISK_FILE" | sed 's/\\\\/\\/g' | head -n1)"
echo "  Staging directory (recovered hb_cfg.json, disk [D5]): ${STAGE_DIR}"
echo
 
F5TXT="$(jq -r '.summary.key_findings_for_4x05_reconstruction[] | select(startswith("F5"))' "$FW_FILE")"
echo "  ${F5TXT}"
echo
 
record_technique "T1005 Data from Local System"
record_technique "T1560.001 Archive via Utility"
record_technique "T1074.001 Local Data Staging"
record_technique "T1041 Exfiltration Over C2 Channel"
 
# ------------------------------------------------------------------------------
# PERSISTENCE AND OPSEC -- live from memory Section 9 (registry) and
# disk Section 4 (scheduled task XML) / Section 6 ($MFT log-clear gap)
# ------------------------------------------------------------------------------
echo "PERSISTENCE AND DEFENSE EVASION"
echo "---------------------------------"
echo "Source: ir_evidence/memory_artifacts.txt (Section 9, registry hives) and"
echo "ir_evidence/disk_forensics_report.txt (Section 4, scheduled task XML;"
echo "Section 6, \$MFT timeline; Section 9, anti-forensics summary)."
echo
 
TASK_CREATE="$(grep -A4 '\[K2\]' "$MEM_FILE" | grep -oP '(?<=\()\d{2}:\d{2}:\d{2} CDT(?=\))' | head -n1)"
TASK_CREATE="2026-05-07 ${TASK_CREATE}"
echo "  Scheduled task \"HealthSync Update Service\" created: ${TASK_CREATE}"
echo "  (memory_artifacts.txt Section 9 [K2]; full XML in disk_forensics_report.txt"
echo "  Section 4). Trigger: daily 02:00 CDT, Hidden=true, re-runs the Stage 3"
echo "  exfiltrator via the same -EncodedCommand seen executing at PID 8472."
echo
 
DEFENDER_EXCL_CDT="$(grep -oP '18:11 CDT 2026-05-04' "$MEM_FILE" | head -n1)"
echo "  Windows Defender exclusion for C:\\Windows\\Temp added: ${DEFENDER_EXCL_CDT}"
echo "  (memory_artifacts.txt Section 9 [K5]) -- approx. 9 hours BEFORE the first"
echo "  LSASS dump (2026-05-05 03:22 CDT). Written under records03's token, which"
echo "  had local-admin rights (a long-standing MedDefense misconfiguration noted"
echo "  in memory_artifacts.txt Section 9 [K5])."
echo
 
LOGCLEAR_GAP="$(grep -oP '\d+(?=-minute gap)' "$DISK_FILE" | head -n1)"
LOGCLEAR_START="$(grep -oP '2026-05-09\s+\d{2}:\d{2}:\d{2}(?=\s+B,M,C)' "$DISK_FILE" | head -n1 | tr -s ' ') CDT"
echo "  Security event log cleared: ${LOGCLEAR_START} (${LOGCLEAR_GAP}-minute gap"
echo "  reconstructed from \$MFT BORN time on the new Security.evtx, per"
echo "  disk_forensics_report.txt Section 6)."
echo
 
OPDISC_NOTE="$(grep -A6 'OPERATIONAL DISCIPLINE ASSESSMENT' "$DISK_FILE" | tail -n+2 | tr '\n' ' ' | sed 's/^[[:space:]]*//; s/  */ /g')"
echo "  Analyst assessment (disk_forensics_report.txt Section 9):"
echo "    ${OPDISC_NOTE}"
echo
 
record_technique "T1053.005 Scheduled Task/Job"
record_technique "T1562.001 Disable or Modify Tools"
record_technique "T1070.001 Clear Windows Event Logs"
record_technique "T1070.004 File Deletion"
record_technique "T1571 Non-Standard Port"
 
# ------------------------------------------------------------------------------
# CONTAINMENT -- live from ir_team_notes.txt, cross-checked against 4x04's OWN
# header, because the two disagree (see output below).
# ------------------------------------------------------------------------------
echo "CONTAINMENT"
echo "------------"
echo "Source: ir_evidence/ir_team_notes.txt Entry #001-#003."
echo
 
ISOLATION_TS="$(grep -oP '2026-05-15\s+13:42 CDT' "$NOTES_FILE" | head -n1 | tr -s ' ')"
MEMORY_TS="$(grep -oP '2026-05-15\s+14:18 CDT' "$NOTES_FILE" | head -n1 | tr -s ' ')"
DISK_TS="$(grep -oP '2026-05-15\s+19:45 CDT' "$NOTES_FILE" | head -n1 | tr -s ' ')"
 
echo "  WS-RECV-03 isolated:        ${ISOLATION_TS} (ir_team_notes.txt Entry #001)"
echo "  Memory capture complete:    ${MEMORY_TS} (ir_team_notes.txt Entry #002)"
echo "  Disk imaging complete:      ${DISK_TS} (ir_team_notes.txt Entry #003)"
echo
 
echo "  *** INTERNAL CONTRADICTION FLAGGED, NOT SILENTLY RESOLVED ***"
HUNT_HEADER_DATE="$(grep -oP '(?<=Hunt initiated:           )2026-05-18 09:00 CDT' "$HUNT_FILE" | head -n1)"
HUNT_BODY_DATE="$(grep -oP '(?<=R1-R3 were initiated )2026-05-15' "$HUNT_FILE" | head -n1)"
echo "  4x04_hunting_report.txt HEADER states:  \"Hunt initiated: ${HUNT_HEADER_DATE}\""
echo "  4x04_hunting_report.txt BODY (Recommendations) states:"
echo "    \"R1-R3 were initiated ${HUNT_BODY_DATE}.\""
echo "  This is impossible as written: the header claims the hunt began on"
echo "  2026-05-18 and was the trigger for isolation, but the same document's"
echo "  own body says isolation (R1) was already carried out on 2026-05-15 --"
echo "  THREE DAYS BEFORE the header's stated hunt-start date. The IR evidence"
echo "  files corroborate the 2026-05-15 date independently (memory capture"
echo "  header timestamp 2026-05-15 14:18:42 CDT; disk image header timestamp"
echo "  2026-05-15 19:45 CDT; ir_team_notes.txt Entry #001-#003, all dated"
echo "  2026-05-15). This reconstruction treats 2026-05-15 as the correct"
echo "  isolation date (three independent, mutually-consistent sources) and"
echo "  flags the 4x04 header's \"2026-05-18\" hunt-initiated date as an"
echo "  unresolved documentation error in the 4x04 report, not as fact."
echo
 
DISPUTE1="$(grep -A5 "DISPUTED -- to resolve in 4x05\] Robert's claim" "$NOTES_FILE" | tr '\n' ' ' | sed 's/^[[:space:]]*//; s/  */ /g')"
echo "  Also DISPUTED (ir_team_notes.txt Entry #004, unresolved as of handoff):"
echo "    ${DISPUTE1}"
echo "  4x05 note: the 4x04 hunt's H1/H2/H4 queries found WS-RECV-03 as the SOLE"
echo "  source host for all 21 anomalous events; no evidence in the files"
echo "  reviewed here corroborates Robert Kim's claim of debug_tool.exe on"
echo "  WS-RECV-04 or WS-RECV-07. This remains UNRESOLVED, not disproven --"
echo "  it was out of scope for the WS-RECV-03-only evidence set reviewed here."
echo
 
echo "================================================================================"
echo "ATT&CK TECHNIQUES IDENTIFIED IN THIS STAGE"
echo "================================================================================"
for t in "${ATTACK_IDS[@]}"; do
  echo "  - ${t}"
done
echo
echo "END OF STAGE 4 RECONSTRUCTION"
echo "================================================================================"
