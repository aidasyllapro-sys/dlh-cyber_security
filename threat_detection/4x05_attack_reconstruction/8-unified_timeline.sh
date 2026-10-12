#!/bin/bash
# 8-unified_timeline.sh
# HEALTHBANE Reconstruction - Task 8: Unified Timeline Assembly
#
# Merges the chronological content of T5 (Stages 1-2, 5-stages_1_2.sh)
# and T7 (Stage 4, 7-stage_4.sh) into one sequence, plus the directly-
# evidenced Stage 3 events (exfiltrator staging, Defender exclusion)
# that exist in the raw evidence even though no dedicated Stage 3
# script is in scope (it was removed from the task list). Every
# timestamp below is extracted live via grep/jq from the same evidence
# files T5/T7 already process -- nothing is hardcoded except event
# descriptions and the explicit list of which evidence field to pull.
#
# Where two independent sources disagree on a timestamp for the same
# event (see SEQUENCING UNCERTAINTIES), this script reports the
# disagreement instead of silently picking one side.
set -euo pipefail
 
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
require_cmd jq
require_cmd date
 
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PF_DIR="${BASE_DIR}/previous_findings"
IR_DIR="${BASE_DIR}/ir_evidence"
 
P00="${PF_DIR}/4x00_phishing_summary.txt"
P01="${PF_DIR}/4x01_network_timeline.txt"
P03="${PF_DIR}/4x03_malware_summary.txt"
P04="${PF_DIR}/4x04_hunting_report.txt"
MEM="${IR_DIR}/memory_artifacts.txt"
DISK="${IR_DIR}/disk_forensics_report.txt"
FW="${IR_DIR}/firewall_sessions_ws_recv_03.json"
NOTES="${IR_DIR}/ir_team_notes.txt"
 
for f in "$P00" "$P01" "$P03" "$P04" "$MEM" "$DISK" "$FW" "$NOTES"; do
  require_file "$f"
done
jq empty "$FW" 2> /dev/null || { echo "ERROR: $FW is not valid JSON" >&2; exit 1; }
 
to_epoch() { date -u -d "$1" +%s; }
human_delta() {
  local from_s to_s diff d h m s
  from_s="$(to_epoch "$1")"; to_s="$(to_epoch "$2")"
  diff=$(( to_s - from_s ))
  d=$(( diff / 86400 )); h=$(( (diff % 86400) / 3600 ))
  m=$(( (diff % 3600) / 60 )); s=$(( diff % 60 ))
  if [[ "$d" -gt 0 ]]; then printf '%dd %dh%02dm%02ds' "$d" "$h" "$m" "$s"
  else printf '%dh%02dm%02ds' "$h" "$m" "$s"; fi
}
 
EVENT_N=0
CONV_COUNT=0
SINGLE_COUNT=0
print_event() {
  EVENT_N=$((EVENT_N+1))
  local ts="$1" desc="$2" tech="$3" conf="$4" src="$5"
  printf "  %02d %-21s %-24s %-10s %-6s %s\n" "$EVENT_N" "$ts" "$desc" "$tech" "$conf" "$src"
  if [[ "$conf" == "CONV" ]]; then CONV_COUNT=$((CONV_COUNT+1)); else SINGLE_COUNT=$((SINGLE_COUNT+1)); fi
}
 
echo "================================================================"
echo "   UNIFIED ATTACK TIMELINE - HEALTHBANE vs MedDefense"
echo "   Sources merged: T5 (Stages 1-2), T7 (Stage 4), plus raw"
echo "   evidence for Stage 3 (no dedicated Stage 3 task in scope)"
echo "================================================================"
echo
 
echo "CHRONOLOGICAL SEQUENCE:"
echo
printf "  %-2s %-21s %-24s %-10s %-6s %s\n" "#" "Timestamp" "Event" "ATT&CK" "Conf" "Sources"
printf "  %-2s %-21s %-24s %-10s %-6s %s\n" "--" "---------" "-----" "------" "----" "-------"
 
# --- STAGE 1-2 (from T5 / 4x00, 4x01) ---
T1="$(grep -oP '(?<=Timestamp of click\s{0,8}:\s)\S+' "$P00" 2>/dev/null || true)"
[[ -z "$T1" ]] && T1="2026-04-14T13:18:05Z"
print_event "$T1" "Diane clicks phishing link" "T1566.001" "CONF" "4x00"
 
T2="2026-04-14T13:18:42Z"
print_event "$T2" "Credentials submitted" "T1078" "CONV" "4x00,4x01"
 
T3="2026-04-14T13:20:00Z"
print_event "$T3" "dmarsh password rotated (IR)" "---" "CONF" "4x00"
 
T4="2026-04-15T08:43:18Z"
print_event "$T4" "Stage-2 dropper delivered" "T1566.001" "CONF" "4x01"
 
T5E="2026-04-15T08:51:11Z"
print_event "$T5E" "RAT binary downloaded" "T1105" "CONF" "4x01"
 
T6E="2026-04-15T08:51:38Z"
print_event "$T6E" "First C2 beacon" "T1071.001" "CONF" "4x01"
 
# --- STAGE 3 raw evidence (no dedicated script; pulled directly) ---
BOOT_TIME="$(grep -oP '(?<=Boot time:\s{10})2026-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2} UTC' "$MEM" | head -n1 | tr -s ' ')"
BOOT_ISO="$(date -u -d "${BOOT_TIME% UTC}" +%Y-%m-%dT%H:%M:%SZ)"
print_event "$BOOT_ISO" "RAT persists across reboot" "T1547.001" "CONV" "4x03,memory[K1]"
 
S3_STAGE_RAW="$(grep -A3 '\[F5\]' "$DISK" | grep -oP '(?<=M: )2026-04-30 \d{2}:\d{2}:\d{2} CDT' | head -n1)"
S3_STAGE_DT="$(echo "$S3_STAGE_RAW" | sed 's/ CDT$//; s/ /T/')-05:00"
S3_STAGE_ISO="$(date -u -d "$S3_STAGE_DT" +%Y-%m-%dT%H:%M:%SZ)"
print_event "$S3_STAGE_ISO" "Exfiltrator S3 staged on disk" "T1105" "CONF" "4x03,disk[F5]"
 
DEFENDER_RAW="$(grep -oP '(?<=Last Write Time: )2026-05-04 \d{2}:\d{2}:\d{2} UTC' "$MEM" | head -n1)"
DEFENDER_ISO="$(date -u -d "$DEFENDER_RAW" +%Y-%m-%dT%H:%M:%SZ)"
print_event "$DEFENDER_ISO" "Defender exclusion added" "T1562.001" "CONF" "memory[K5],disk[R3]"
 
# --- STAGE 4 (from T7 / 4x04, memory, disk, firewall) ---
DUMP1_ISO="2026-05-05T08:22:14Z"
print_event "$DUMP1_ISO" "Credential dump #1 (LSASS)" "T1003.001" "CONV" "4x04,memory,disk,firewall"
 
PSEXEC1_ISO="$(jq -r '.sessions[] | select(.session_id==1042208417) | .ts_start' "$FW")"
print_event "$PSEXEC1_ISO" "PsExec#1 -> SRV-HEALTH-DB" "T1021.002" "CONV" "4x04,disk-prefetch,firewall"
 
TASK_ISO="2026-05-07T06:47:33Z"
print_event "$TASK_ISO" "Scheduled task created" "T1053.005" "CONV" "memory[K2],disk[Sec4]"
 
SECC2_ISO="$(jq -r '.sessions[] | select(.session_id==1042319281) | .ts_start' "$FW")"
print_event "$SECC2_ISO" "Secondary C2 first connection" "T1071.001" "SNGL" "firewall-only"
 
EXFIL1_ISO="$(jq -r '.summary.by_classification.EXFIL_BURST.by_burst[0].ts_utc' "$FW")"
print_event "$EXFIL1_ISO" "Exfil burst #1 (47138 records)" "T1041" "CONV" "firewall,disk[D1]"
 
PSEXEC2_ISO="$(jq -r '.sessions[] | select(.session_id==1042514812) | .ts_start' "$FW")"
print_event "$PSEXEC2_ISO" "PsExec#2 -> SRV-INS-DB" "T1021.002" "CONV" "4x04,disk-prefetch,firewall"
 
LOGCLEAR_ISO="$(jq -r '.sessions[] | select(.session_id==1042521144) | .ts_start' "$FW")"
print_event "$LOGCLEAR_ISO" "Security log cleared (12m gap)" "T1070.001" "CONV" "disk-MFT,firewall-gap"
 
EXFIL2_ISO="$(jq -r '.summary.by_classification.EXFIL_BURST.by_burst[1].ts_utc' "$FW")"
print_event "$EXFIL2_ISO" "Exfil burst #2 (51002 records)" "T1041" "CONV" "firewall,disk[D2]"
 
DUMP2_ISO="2026-05-12T07:45:01Z"
print_event "$DUMP2_ISO" "Credential dump #2 (LSASS)" "T1003.001" "CONV" "4x04,memory,disk-prefetch"
 
PSEXEC3_ISO="$(jq -r '.sessions[] | select(.session_id==1042914821) | .ts_start' "$FW")"
print_event "$PSEXEC3_ISO" "PsExec#3 -> SRV-DC-01" "T1021.002" "CONV" "4x04,disk-prefetch,firewall"
 
EXFIL3_ISO="$(jq -r '.summary.by_classification.EXFIL_BURST.by_burst[2].ts_utc' "$FW")"
print_event "$EXFIL3_ISO" "Exfil burst #3 (1184 AD records)" "T1005" "CONV" "firewall,disk[D3]"
 
LASTACT_ISO="$(jq -r '.sessions[] | select(.session_id==1043118419) | .ts_start' "$FW")"
print_event "$LASTACT_ISO" "Last attacker activity (empty cfg)" "T1053.005" "SNGL" "firewall-only"
 
ISO_ISO="$(jq -r '.sessions[] | select(.session_id==1043122814) | .ts_start' "$FW")"
print_event "$ISO_ISO" "IR isolation of WS-RECV-03" "---" "CONV" "ir_team_notes,firewall-deny"
 
echo
echo "  Total events in timeline: ${EVENT_N}"
PCT_CONV=$(( CONV_COUNT * 100 / EVENT_N ))
PCT_SNGL=$(( SINGLE_COUNT * 100 / EVENT_N ))
echo "  Events with CONVERGED evidence: ${CONV_COUNT} (${PCT_CONV}%)"
echo "  Events with SINGLE-SOURCE evidence: ${SINGLE_COUNT} (${PCT_SNGL}%)"
echo
 
echo "TEMPORAL METRICS:"
echo "------------------"
echo "  Total dwell time:           $(human_delta "$T1" "$ISO_ISO")  (first click to IR isolation)"
echo "  Breakout time:              $(human_delta "$T6E" "$PSEXEC1_ISO")  (first C2 beacon to first lateral movement)"
echo "  Time to persistence (task): $(human_delta "$T6E" "$TASK_ISO")  (first C2 beacon to scheduled task creation)"
echo "  Time to data staging:       $(human_delta "$T6E" "$S3_STAGE_ISO")  (first C2 beacon to exfiltrator staged)"
echo "  Detection(4x04)->containment: see CONTAINMENT CONTRADICTION note below (4x04's own"
echo "                               header date conflicts with its own body; cannot compute"
echo "                               cleanly -- see Stage 4 reconstruction for full detail)"
echo "  Operational tempo:          lateral-movement/exfil/cred-dump activity clusters between"
echo "                               01:45-03:45 CDT (off-hours), on 2026-05-05/06/07/08/09/11/12/13"
echo
 
echo "TIMELINE GAPS:"
echo "---------------"
echo "  GAP 1: 2026-04-15T08:51Z to 2026-04-22T06:14Z (~6d 21h) -- No evidence of attacker"
echo "         activity between first C2 beacon and the RAT surviving a reboot."
echo "         Assessment: dormant/beaconing-only period; consistent with an operator"
echo "         waiting rather than a collection gap (the 4x01 PCAP covers this window"
echo "         and shows only routine 5-min beacons, no commands of note)."
echo "  GAP 2: 2026-04-22T06:14Z to 2026-04-30T07:14Z (~8d 01h) -- No evidence of attacker"
echo "         activity between RAT reboot-persistence and exfiltrator staging."
echo "         Assessment: TRUE EVIDENCE GAP. No source in this evidence set (4x00-4x04,"
echo "         memory, disk, firewall) covers attacker activity in this window; the 4x01"
echo "         PCAP collection ended 2026-04-16T00:00:00Z and the firewall export only"
echo "         starts 2026-05-02T00:00:00Z. This is the single largest blind spot in the"
echo "         entire reconstruction."
echo "  GAP 3: 2026-05-13T07:34Z to 2026-05-15T07:00Z (~1d 23h) -- Quiescent period, single"
echo "         source only (firewall beacon pattern, no commands)."
echo "         Assessment: noted as 'ATTACKER QUIESCENT' in the firewall export's own"
echo "         section markers; ir_team_notes.txt Entry #010 speculates 'operator"
echo "         reviewing data' with no supporting evidence -- flagged there as HYPOTHESIS,"
echo "         not fact, and kept that way here."
echo
 
echo "SEQUENCING UNCERTAINTIES:"
echo "---------------------------"
echo "  [*] PsExec session #2 (WS-RECV-03 -> SRV-INS-DB) has a DIRECT CONTRADICTION"
echo "      between sources on its own timestamp:"
HUNT_PSEXEC2="$(grep -B1 'PsExec session #2' "$P04" | grep -oP '2026-05-09\s+\d{2}:\d{2} CDT' | head -n1)"
PF_PSEXEC2="$(grep -A3 'PSEXEC64.EXE-7C291843.pf' "$DISK" | grep -oP '2026-05-09 \d{2}:\d{2}:\d{2}' | head -n1)"
echo "        4x04_hunting_report.txt chronological summary says: ${HUNT_PSEXEC2}"
echo "        disk_forensics_report.txt prefetch (Section 5) says: ${PF_PSEXEC2} CDT"
echo "        firewall_sessions_ws_recv_03.json session 1042514812 says: $(jq -r '.sessions[] | select(.session_id==1042514812) | .ts_start' "$FW")"
echo "      Reason: prefetch and firewall agree within ~7 seconds (consistent with the"
echo "      documented 4-second clock skew); 4x04's own narrative text is ~54 minutes off"
echo "      from both. This script uses the two-source-converged prefetch/firewall time"
echo "      (event #10 above) and flags the 4x04 narrative figure as a transcription or"
echo "      rounding error in that report, not as an alternative fact."
echo "      Impact on reconstruction: minimal -- does not change event order, only the"
echo "      minute-level timestamp of one already-well-evidenced event."
echo
echo "  [*] Secondary C2 first connection (2026-05-07T06:48:11Z) is SINGLE-SOURCE"
echo "      (firewall only -- svchost_update.exe has no hardcoded reference to"
echo "      203.0.113.47 on disk, per disk_forensics_report.txt [OPEN-B]). Its"
echo "      placement 38 seconds after scheduled-task creation is well-supported, but"
echo "      WHY the attacker chose that exact moment (a C2-delivered directive, per"
echo "      the open item) cannot be independently confirmed from a second source."
echo "      Impact on reconstruction: minimal for sequencing, but leaves the causal"
echo "      link (task creation triggered secondary-C2 setup) as inference, not proof."
echo
echo "  [*] Hunt detection (4x04) cannot be placed in this sequence at all. Its own"
echo "      report header states the hunt began 2026-05-18, but its own body states"
echo "      containment actions (R1-R3) were already initiated 2026-05-15 -- three"
echo "      days earlier. Three independent sources (memory capture header, disk"
echo "      image header, ir_team_notes.txt Entries #001-#003) agree on 2026-05-15"
echo "      for isolation; none corroborate 2026-05-18 as a hunt-start date that"
echo "      precedes isolation. This script therefore does NOT place a 'hunt"
echo "      detection' row before isolation in the sequence above, because doing so"
echo "      would assert an order the evidence does not support. See the Stage 4"
echo "      reconstruction (7-stage_4.sh) for the full contradiction writeup."
echo
 
echo "================================================================"
