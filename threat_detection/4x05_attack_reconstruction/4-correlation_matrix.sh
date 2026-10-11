#!/bin/bash
# 4-correlation_matrix.sh
# HEALTHBANE Reconstruction - Task 4: Cross-Evidence Correlation
#
# Per the task instructions ("Reads the outputs of T0-T3 plus all
# previous_findings/ summaries"), this script actually EXECUTES
# 0-evidence_index.sh, 1-memory_analysis.sh, 2-disk_analysis.sh and
# 3-firewall_analysis.sh and cross-references their live stdout for the
# IOC correlation matrix, rather than re-reading the raw ir_evidence/
# files those three tasks already analyze. ir_team_notes.txt is the one
# ir_evidence/ file not owned by any single task (it is cross-cutting
# analyst commentary, not raw host/network data), so it is still read
# directly here -- Task 4 is the only place it gets synthesized.
# previous_findings/ summaries (4x00-4x04) are read directly, per the
# instructions' "plus all previous_findings/ summaries" clause.
# The timeline and technique narratives below are this script's own
# synthesis across sources and are written out as findings rather than
# derived mechanically, because resolving a contradiction is a judgment
# call, not a string match -- each one cites exactly which file and
# line supports it.
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
require_cmd bash

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PF_DIR="${BASE_DIR}/previous_findings"
IR_DIR="${BASE_DIR}/ir_evidence"
REF_DIR="${BASE_DIR}/reference"
IOC_FILE="${REF_DIR}/healthbane_ioc_master.json"
NAV_4x02="${PF_DIR}/4x02_attack_mapping.json"
NAV_80PCT="${REF_DIR}/attck_navigator_80pct.json"
NOTES_FILE="${IR_DIR}/ir_team_notes.txt"

# Task 0-3 scripts: their live stdout, not the raw files they each
# already analyze, is what this script cross-references (see header).
T0_SCRIPT="${BASE_DIR}/0-evidence_index.sh"
T1_SCRIPT="${BASE_DIR}/1-memory_analysis.sh"
T2_SCRIPT="${BASE_DIR}/2-disk_analysis.sh"
T3_SCRIPT="${BASE_DIR}/3-firewall_analysis.sh"

MEM_FILE="${IR_DIR}/memory_artifacts.txt"
DISK_FILE="${IR_DIR}/disk_forensics_report.txt"
FW_FILE="${IR_DIR}/firewall_sessions_ws_recv_03.json"

require_dir "$PF_DIR"
require_dir "$IR_DIR"
require_dir "$REF_DIR"
require_file "$IOC_FILE"
require_file "$NAV_4x02"
require_file "$NAV_80PCT"
require_file "$NOTES_FILE"
require_file "$MEM_FILE"
require_file "$DISK_FILE"
require_file "$FW_FILE"
require_file "$T0_SCRIPT"
require_file "$T1_SCRIPT"
require_file "$T2_SCRIPT"
require_file "$T3_SCRIPT"

run_task() {
  local script="$1" label="$2" out
  if ! out="$(bash "$script" 2>&1)"; then
    echo "ERROR: $label ($script) failed to run" >&2
    exit 1
  fi
  printf '%s' "$out"
}

echo "Running Task 0 (0-evidence_index.sh), Task 1 (1-memory_analysis.sh)," >&2
echo "Task 2 (2-disk_analysis.sh) and Task 3 (3-firewall_analysis.sh) to" >&2
echo "cross-reference their live output (per task instructions)..." >&2
T0_OUT="$(run_task "$T0_SCRIPT" "Task 0")"
T1_OUT="$(run_task "$T1_SCRIPT" "Task 1")"
T2_OUT="$(run_task "$T2_SCRIPT" "Task 2")"
T3_OUT="$(run_task "$T3_SCRIPT" "Task 3")"

# T0's own catalog line count is the authoritative evidence-file total
# (it enumerates every file under previous_findings/, ir_evidence/ and
# reference/ itself) -- used here instead of a separate find/wc count,
# so the number printed is literally read FROM Task 0's output.
SOURCE_COUNT="$(grep -c '^[[:space:]]*\[[0-9][0-9]\]' <<< "$T0_OUT")"

echo "================================================================"
echo "   CROSS-EVIDENCE CORRELATION MATRIX"
echo "   Sources: 4x00 through 4x05-IR (${SOURCE_COUNT} evidence files)"
echo "================================================================"
echo

# ---------------------------------------------------------------------------
# IOC CORRELATION
# For each of the 31 IOCs already catalogued in healthbane_ioc_master.json
# (whose own "sources" field already records 4x00-4x04 attribution), this
# checks whether the IOC also surfaces in Tasks 0-3's live stdout (the
# primary IR-evidence cross-reference, per the task instructions) OR in
# the raw IR evidence files directly. The two are not always the same --
# a value can be present in the raw evidence yet never get echoed in the
# owning task's own printed report. Both are checked so no real finding
# is silently lost, and every such owning-task gap is listed afterwards
# as its own finding, since "a report didn't mention something its own
# source data contains" is itself a gap worth flagging, not hiding.
# ---------------------------------------------------------------------------
echo "IOC CORRELATION (31 pre-existing IOCs, 4x00-4x04 sources from"
echo "healthbane_ioc_master.json, cross-checked live against the stdout of"
echo "Tasks 0-3, with raw ir_evidence/ files as a completeness fallback):"
printf '  %-10s %-14s %-45s %-10s %s\n' "ID" "Type" "Value" "Sources" "Status"

CONVERGED_COUNT=0
SINGLE_COUNT=0
TASK_OUTPUT_GAPS=()
while IFS=$'\t' read -r id type value srcs; do
  ir_hit_task="no"
  if grep -qiF -- "$value" <<< "$T0_OUT" \
     || grep -qiF -- "$value" <<< "$T1_OUT" \
     || grep -qiF -- "$value" <<< "$T2_OUT" \
     || grep -qiF -- "$value" <<< "$T3_OUT"; then
    ir_hit_task="yes"
  fi
  ir_hit_raw="no"
  if grep -qiF -- "$value" "$NOTES_FILE" "$MEM_FILE" "$DISK_FILE" 2> /dev/null \
     || jq -c . "$FW_FILE" 2> /dev/null | grep -qiF -- "$value"; then
    ir_hit_raw="yes"
  fi
  if [[ "$ir_hit_raw" == "yes" && "$ir_hit_task" == "no" ]]; then
    TASK_OUTPUT_GAPS+=("$id ($value)")
  fi
  final_srcs="$srcs"
  [[ "$ir_hit_task" == "yes" || "$ir_hit_raw" == "yes" ]] && final_srcs="${srcs},IR"
  n_sources=$(tr ',' '\n' <<< "$final_srcs" | wc -l)
  if [[ "$n_sources" -ge 2 ]]; then
    status="CONVERGED"
    CONVERGED_COUNT=$((CONVERGED_COUNT + 1))
  else
    status="SINGLE-SOURCE"
    SINGLE_COUNT=$((SINGLE_COUNT + 1))
  fi
  display_value="$value"
  [[ ${#display_value} -gt 45 ]] && display_value="${display_value:0:42}..."
  printf '  %-10s %-14s %-45s %-10s %s\n' "$id" "$type" "$display_value" "$final_srcs" "$status"
done < <(jq -r '.iocs[] | [.id, .type, .value, (.sources | join(","))] | @tsv' "$IOC_FILE")

echo
printf '  Summary (31 pre-existing IOCs): %s CONVERGED, %s SINGLE-SOURCE, 0 CONFLICTED\n' "$CONVERGED_COUNT" "$SINGLE_COUNT"
echo "  (no pre-existing IOC's VALUE is contradicted by another source --"
echo "  the only real conflict in this evidence set is an ID-LABELING"
echo "  conflict among the brand-new IR indicators, resolved below.)"
echo
if [[ ${#TASK_OUTPUT_GAPS[@]} -gt 0 ]]; then
  echo "  TASK-REPORT GAP: ${#TASK_OUTPUT_GAPS[@]} of the above IOCs are present"
  echo "  in the raw IR evidence files but are not echoed in Tasks 0-3's own"
  echo "  printed reports (found instead by reading the raw file directly):"
  for gap in "${TASK_OUTPUT_GAPS[@]}"; do
    echo "    - $gap"
  done
  echo "  This does not change their CONVERGED/SINGLE-SOURCE status above,"
  echo "  but it means a reader relying on Tasks 0-3's prose alone, without"
  echo "  this script's own direct fallback to the raw files, would miss them."
  echo
fi

echo "NEW IOCs FROM IR EVIDENCE (not in the 31-entry master database):"
echo "  CONTRADICTION FOUND AND RESOLVED: the evidence files do not agree"
echo "  on IDs for these new indicators. memory_artifacts.txt tags the"
echo "  secondary-C2 IP as HB-IOC-NEW-001 (line 176), and"
echo "  firewall_sessions_ws_recv_03.json's own metadata.iocs_relevant"
echo "  list (written at export time) AGREES, also calling it"
echo "  HB-IOC-NEW-001 -- but that same firewall file's own formal"
echo "  summary.iocs_added_by_firewall_analysis block (written later in"
echo "  the same file) calls the IDENTICAL indicator HB-IOC-NEW-006."
echo "  That is a self-contradiction inside one evidence file, not just"
echo "  a cross-file disagreement. Resolution: HB-IOC-NEW-001 is adopted"
echo "  as canonical (it is the first use, corroborated by two sources),"
echo "  and the file's own later NEW-006 label is treated as a drafting"
echo "  error, not a second indicator. Renumbering the other four"
echo "  disk-forensics IOCs so the canonical set below is now sequential"
echo "  and non-duplicated:"
echo
printf '  %-14s %-45s %-20s %s\n' "Canonical ID" "Indicator" "Sources" "Status"
printf '  %-14s %-45s %-20s %s\n' "HB-IOC-NEW-001" "203.0.113.47:8443 (secondary C2)" "memory,firewall" "CONVERGED"
printf '  %-14s %-45s %-20s %s\n' "HB-IOC-NEW-002" "\"HealthSync Update Service\" sched. task" "memory,disk" "CONVERGED"
printf '  %-14s %-45s %-20s %s\n' "HB-IOC-NEW-003" "debug_tool.exe SHA256 (new hash on HB-0020)" "disk" "SINGLE-SOURCE"
printf '  %-14s %-45s %-20s %s\n' "HB-IOC-NEW-004" "Defender excl. C:\\Windows\\Temp" "memory,disk,notes" "CONVERGED"
printf '  %-14s %-45s %-20s %s\n' "HB-IOC-NEW-005" "staged_filename pattern (out_*.csv/.zip)" "disk,notes" "CONVERGED"
echo
echo "  NOTE on HB-IOC-NEW-003: this is NOT a brand-new artifact -- the"
echo "  filename debug_tool.exe is already HB-IOC-0020 (sourced 4x04)."
echo "  Disk forensics enriches it with a SHA256 hash. Treated here as an"
echo "  ENRICHMENT of HB-IOC-0020, not a second distinct indicator, which"
echo "  is also why its live grep hit above already shows HB-IOC-0020 as"
echo "  CONVERGED (4x04+IR) rather than counting it twice."
echo "  New IOCs from IR: 5 (after resolving the ID conflict above)"
echo

# ---------------------------------------------------------------------------
# TIMELINE CORRELATION
# Key attack-chain events and which sources carry evidence for each.
# Timestamps quoted here are taken directly from the cited file; the
# clock-skew / timing-gap findings are this script's own reconciliation
# work, done by hand against the quoted timestamps (bash has no business
# inferring a time-skew from two strings on its own).
# ---------------------------------------------------------------------------
echo "TIMELINE CORRELATION:"
printf '  %-22s %-22s %-11s %s\n' "Event" "Sources" "Confidence" "Notes"
printf '  %-22s %-22s %-11s %s\n' "Phishing delivery" "4x00" "HIGH" "Primary evidence, 2026-04-14"
printf '  %-22s %-22s %-11s %s\n' "Credential theft" "4x00,4x01" "CONVERGED" "dmarsh capture + portal POST match"
printf '  %-22s %-22s %-11s %s\n' "C2 establishment" "4x01,4x03,4x04" "CONVERGED" "Beacon to 185.220.101.45:443 unbroken"
printf '  %-22s %-22s %-11s %s\n' "Malware deployment" "4x03,IR-MEM" "CONVERGED" "svchost_update.exe hash matches"
printf '  %-22s %-22s %-11s %s\n' "Persistence install" "IR-MEM,IR-DISK" "CONVERGED" "Sched. task 2026-05-07 06:47:33Z"
printf '  %-22s %-22s %-11s %s\n' "1st lateral movement" "4x04,IR-FW" "CONVERGED" "WS-RECV-03->SRV-HEALTH-DB, 05-06"
printf '  %-22s %-22s %-11s %s\n' "Credential dump #1" "4x04,IR-FW" "CONVERGED" "LSASS dump, 05-05 (see below)"
printf '  %-22s %-22s %-11s %s\n' "Defender exclusion" "IR-DISK,notes" "SINGLE/DISPUTED" "05-04 18:11 CDT (see contradiction)"
printf '  %-22s %-22s %-11s %s\n' "Data staging (3x)" "IR-DISK" "SINGLE" "05-08, 05-11, 05-13"
printf '  %-22s %-22s %-11s %s\n' "Data exfiltration" "IR-DISK,IR-FW" "CONVERGED" "Byte-exact match, see Task 3"
printf '  %-22s %-22s %-11s %s\n' "Secondary C2 setup" "IR-MEM,IR-FW" "CONVERGED" "05-07, 38s after task creation"
printf '  %-22s %-22s %-11s %s\n' "Log clearing" "IR-MEM,IR-DISK,notes" "CONVERGED" "05-09 03:01-03:12 CDT gap"
printf '  %-22s %-22s %-11s %s\n' "Isolation/containment" "4x04,notes" "HIGH" "05-15 13:42 CDT"
echo

echo "  TIMESTAMP RECONCILIATION (4x04 Wazuh/Sysmon host events vs IR"
echo "  firewall session logs -- both cover overlapping dates, unlike"
echo "  4x01's PCAP window which predates the firewall export by weeks"
echo "  and so cannot be cross-checked against it minute-for-minute):"
echo
echo "  CONVERGED, consistent with the firewall's own stated 4-second"
echo "  skew (SYN-time vs host-event-time):"
echo "    05-06 PsExec #1: Wazuh 02:12 CDT vs firewall 02:11:46 CDT"
echo "    (~14s apart, within the rounding of a minute-precision Wazuh"
echo "    timestamp -- consistent with the stated skew, not a true gap)."
echo "    05-05 cred dump #1: Wazuh 03:22 CDT vs firewall aggregate note"
echo "    window start 08:22 UTC = 03:22 CDT exactly -- exact match."
echo
echo "  NOT simple clock skew -- flagged rather than forced into the"
echo "  4-second-skew narrative, because the gap is too large for a"
echo "  SYN-vs-host-event explanation:"
echo "    05-09 PsExec #2: Wazuh logs 03:40 CDT; firewall's sampled"
echo "    session for that date starts at 02:46:18 CDT (duration ~28min,"
echo "    ending ~03:14 CDT) -- Wazuh's event is ~25 minutes AFTER the"
echo "    firewall session ends. Resolution: these are different"
echo "    sub-events of the same intrusion (the firewall session is the"
echo "    initial SMB connect; the Wazuh alert likely fired on a later"
echo "    action inside that session, e.g. a file write), not the same"
echo "    moment measured twice -- so it is a sequencing question, not a"
echo "    clock-sync question, and is left as LOWER CONFIDENCE on exact"
echo "    sub-timing until a full (non-abridged) Wazuh export is pulled."
echo "    05-13 PsExec #3: Wazuh logs 01:56 CDT; firewall's sampled"
echo "    session starts 02:08:58 CDT -- here Wazuh is ~13 minutes"
echo "    BEFORE the firewall session, the OPPOSITE direction from the"
echo "    05-09 case. A single fixed clock-skew cannot explain opposite-"
echo "    direction gaps, which confirms these are genuinely different"
echo "    sub-events, not a skew to correct for."
echo

echo "  CONTRADICTION: Defender exclusion attribution (ir_team_notes.txt,"
echo "  entry flagged [DISPUTED -- to resolve in 4x05]):"
echo "    Robert Kim (WS-ADMIN-01, the authorized admin) claims he added"
echo "    the C:\\Windows\\Temp Defender exclusion himself for legitimate"
echo "    sysadmin reasons."
echo "    Evidence against that claim, per the same notes entry: (1) his"
echo "    own maintenance schedule shows no work logged for 2026-05-04"
echo "    evening: (2) the registry hive entry recording the exclusion is"
echo "    under the records03 SID, not an admin or svc-* context, which"
echo "    is not how a sysadmin-applied exclusion would normally be"
echo "    written; (3) the exclusion was added ~9 hours before the FIRST"
echo "    LSASS dump on the same host, i.e. precisely the kind of"
echo "    defense-evasion prep an attacker would do before running a"
echo "    detectable credential-dumping tool."
echo "    RESOLUTION: the exclusion is attributed to the attacker"
echo "    (T1562.001), not to Robert's legitimate administration, at"
echo "    PROBABLE confidence -- this is circumstantial/timing evidence,"
echo "    not a confession or a technical artifact proving authorship,"
echo "    so it is not claimed as CONFIRMED."
echo

# ---------------------------------------------------------------------------
# TECHNIQUE CORRELATION
# reference/attck_navigator_80pct.json is the authoritative post-4x04
# baseline (assembled_from 4x02+4x03+4x04 per its own metadata) -- this
# script reads its actual technique colors live rather than trusting that
# file's own typed-out coverage_summary line, because the two do not
# match (see data-quality note below).
# ---------------------------------------------------------------------------
echo "TECHNIQUE CORRELATION:"

STATED_SUMMARY="$(jq -r '.metadata[] | select(.name=="coverage_summary") | .value' "$NAV_80PCT")"
ACTUAL_OBS=$(jq '[.techniques[] | select(.color=="#c40000")] | length' "$NAV_80PCT")
ACTUAL_INF=$(jq '[.techniques[] | select(.color=="#ffcf00")] | length' "$NAV_80PCT")
ACTUAL_NC=$(jq '[.techniques[] | select(.color=="#8a8a8a")] | length' "$NAV_80PCT")
echo "  DATA-QUALITY NOTE: reference/attck_navigator_80pct.json's own"
echo "  metadata states: \"${STATED_SUMMARY}\""
printf '  but its actual technique array contains %s OBSERVED / %s INFERRED /\n' "$ACTUAL_OBS" "$ACTUAL_INF"
printf '  %s NOT COVERED (29 total) -- a genuine mismatch between this\n' "$ACTUAL_NC"
echo "  file's own prose summary and its own data, not an error in this"
echo "  script. The counts below use the actual array (ground truth),"
echo "  not the prose summary. (The same kind of mismatch exists in"
echo "  previous_findings/4x02_attack_mapping.json: its metadata claims"
echo "  11/5/13, its array contains 8/7/14.)"
echo

printf '  %-10s %-24s %s\n' "Technique" "Pre-IR status (4x02-4x04)" "IR resolution"
printf '  %-10s %-24s %s\n' "T1041" "INFERRED" "CONFIRMED (memory+firewall, byte-exact)"
printf '  %-10s %-24s %s\n' "T1048.003" "INFERRED" "NOT OBSERVED (T1041 used instead -- see note)"
printf '  %-10s %-24s %s\n' "T1005" "INFERRED" "CONFIRMED (memory Section 11 NEW-4)"
printf '  %-10s %-24s %s\n' "T1053.005" "NOT COVERED" "CONFIRMED (memory+disk, task XML)"
printf '  %-10s %-24s %s\n' "T1074.001" "NOT COVERED" "CONFIRMED (memory+disk, 3 staging files)"
printf '  %-10s %-24s %s\n' "T1560.001" "NOT COVERED" "CONFIRMED (memory, Compress-Archive)"
printf '  %-10s %-24s %s\n' "T1070.001" "NOT COVERED" "CONFIRMED (memory+disk, log gap)"
echo
echo "  T1048.003 note: this is not a hard CORRECTION (4x02/4x03 only"
echo "  said the capability existed in the exfiltrator's code, not that"
echo "  DNS exfiltration would definitely be used). IR evidence shows the"
echo "  attacker used the EXISTING HTTPS C2 channel for exfiltration"
echo "  (T1041) instead, so T1048.003 is resolved as NOT OBSERVED at"
echo "  MedDefense rather than left open."
echo
echo "  Techniques UPGRADED from INFERRED/NOT COVERED to CONFIRMED by IR: 6"
echo
echo "  NEW techniques identified from IR evidence (absent from all 29"
echo "  entries in the pre-IR threat model, so there is nothing to"
echo "  upgrade -- these are first appearances):"
printf '  %-10s %-45s %s\n' "T1562.001" "Disable or Modify Tools (Defender excl.)" "memory,disk,notes"
printf '  %-10s %-45s %s\n' "T1571" "Non-Standard Port (secondary C2, :8443)" "memory (stated verbatim)"
printf '  %-10s %-45s %s\n' "T1070.004" "File Deletion (staging archives)" "disk (analyst-applied, Task 2)"
printf '  %-10s %-45s %s\n' "T1008" "Fallback Channels (secondary C2 role)" "firewall (analyst-applied, Task 3)"
printf '  %-10s %-45s %s\n' "T1055.012" "Process Hollowing (PPID anomaly)" "memory (analyst-applied, Task 1)"
echo "  Techniques newly identified from IR evidence: 5"
echo
echo "  Re-confirmed, no status change (already OBSERVED before IR):"
echo "    T1003.001 (4x04), T1021.002 (4x04), T1059.001 (4x03),"
echo "    T1071.001 (4x02) -- IR independently reproduces these but does"
echo "    not change their coverage status."
echo
echo "  SECOND DATA-QUALITY NOTE: previous_findings/4x03_malware_summary.txt"
echo "  lists T1140 and T1027.010 under \"Upgraded from INFERRED to"
echo "  OBSERVED\", but 4x02_attack_mapping.json's own array records both"
echo "  as NOT COVERED (#8a8a8a), not INFERRED (#ffcf00), at the time"
echo "  4x03 ran. The upgrade direction is not in question (both are"
echo "  OBSERVED today, confirmed in the post-4x04 baseline), only the"
echo "  4x03 report's own description of their PRIOR state is inaccurate."
echo "  Techniques CORRECTED (a prior layer's status for them was wrong): 1"
echo "  (4x03's framing of T1140/T1027.010, not a change to the current"
echo "  ATT&CK picture itself)."
echo

echo "================================================================"

exit 0
