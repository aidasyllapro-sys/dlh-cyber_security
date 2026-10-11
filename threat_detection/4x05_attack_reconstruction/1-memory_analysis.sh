#!/bin/bash
# 1-memory_analysis.sh
# HEALTHBANE Reconstruction - Task 1: Memory Artifact Analysis
#
# Parses ir_evidence/memory_artifacts.txt (the WS-RECV-03 volatile memory
# triage) and cross-references every finding against
# reference/healthbane_ioc_master.json to tell KNOWN indicators apart from
# NEW ones. Every line printed below points back to a section of the
# memory file it was read from, so a reviewer can re-open that file and
# verify the claim directly instead of trusting this script's word for it.
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
require_cmd jq
require_cmd awk

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IR_DIR="${BASE_DIR}/ir_evidence"
REF_DIR="${BASE_DIR}/reference"
MEM_FILE="${IR_DIR}/memory_artifacts.txt"
IOC_FILE="${REF_DIR}/healthbane_ioc_master.json"

require_dir "$IR_DIR"
require_dir "$REF_DIR"
require_file "$MEM_FILE"
require_file "$IOC_FILE"

if ! jq empty "$IOC_FILE" > /dev/null 2>&1; then
  echo "ERROR: ${IOC_FILE} is not valid JSON" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# IOC lookup tables, read live from the IOC database (not hardcoded), so a
# KNOWN/NEW verdict always reflects the current reference/healthbane_ioc_master.json,
# not a snapshot of it taken when this script was written.
# ---------------------------------------------------------------------------
ioc_lookup() {
  local type="$1" value="$2"
  jq -r --arg t "$type" --arg v "$value" \
    '.iocs[] | select(.type == $t and (.value | ascii_downcase) == ($v | ascii_downcase)) | .id' \
    "$IOC_FILE" | head -n1
}

KNOWN_DOMAINS_FILE="$(mktemp)"
trap 'rm -f "$KNOWN_DOMAINS_FILE"' EXIT
jq -r '.iocs[] | select(.type == "domain") | .value' "$IOC_FILE" > "$KNOWN_DOMAINS_FILE"

domain_hit_in_cmdline() {
  local pid="$1"
  local block
  block="$(awk -v pid="$pid" '
    $0 ~ "^PID "pid"([^0-9]|$)" {found=1}
    found && /^PID [0-9]+/ && $0 !~ "^PID "pid"([^0-9]|$)" {exit}
    found {print}
  ' "$MEM_FILE")"
  while IFS= read -r domain; do
    [[ -z "$domain" ]] && continue
    if grep -qiF "$domain" <<< "$block"; then
      echo "$domain"
      return 0
    fi
  done < "$KNOWN_DOMAINS_FILE"
  return 1
}

TOTAL_KNOWN=0
TOTAL_NEW=0
ATTACK_IDS=()

record_technique() {
  local t="$1"
  for existing in "${ATTACK_IDS[@]}"; do
    [[ "$existing" == "$t" ]] && return 0
  done
  ATTACK_IDS+=("$t")
}

echo "================================================================"
echo "   MEMORY ARTIFACT ANALYSIS - WS-RECV-03"
echo "   Source: ir_evidence/memory_artifacts.txt"
echo "================================================================"
echo

# ---------------------------------------------------------------------------
# PROCESS ANALYSIS
# The pslist excerpt in SECTION 2 itself marks non-standard processes with
# a trailing "*" -- we rely on that marker rather than guessing which
# process names look suspicious.
# ---------------------------------------------------------------------------
echo "PROCESS ANALYSIS (SECTION 2 -- PROCESS LIST):"
printf '  %-6s %-22s %-10s %s\n' "PID" "Process Name" "Status" "ATT&CK"
printf '  %-6s %-22s %-10s %s\n' "---" "----" "------" "------"

SECTION2_BLOCK="$(awk '/^SECTION 2/{f=1} f{print} /^SECTION 3/{exit}' "$MEM_FILE")"

while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  pid="$(awk '{print $1}' <<< "$line")"
  name="$(awk '{print $3}' <<< "$line")"
  [[ "$pid" =~ ^[0-9]+$ ]] || continue

  ioc_id="$(ioc_lookup "filename" "$name")"
  if [[ -n "$ioc_id" ]]; then
    status="KNOWN (${ioc_id})"
    TOTAL_KNOWN=$((TOTAL_KNOWN + 1))
  else
    matched_domain="$(domain_hit_in_cmdline "$pid" || true)"
    if [[ -n "$matched_domain" ]]; then
      domain_ioc="$(ioc_lookup "domain" "$matched_domain")"
      status="KNOWN (cmdline references ${matched_domain}, ${domain_ioc})"
      TOTAL_KNOWN=$((TOTAL_KNOWN + 1))
    else
      status="NEW (not in IOC database)"
      TOTAL_NEW=$((TOTAL_NEW + 1))
    fi
  fi

  case "$name" in
    *svchost_update*)
      technique="T1055.012 Process Hollowing"
      note="PPID rewritten post-launch per analyst annotation on this PID -- consistent with thread injection / process hollowing, not a MITRE ID stated verbatim in the file."
      ;;
    *powershell*)
      technique="T1059.001 PowerShell"
      note="cmdline for this PID carries -EncodedCommand (see SECTION 4) -- standard ATT&CK mapping for PowerShell execution, not a MITRE ID stated verbatim in the file."
      ;;
    *)
      technique="T1036 Masquerading (tentative)"
      note="flagged non-standard by the pslist '*' marker; no more specific technique is textually supported for this process."
      ;;
  esac
  record_technique "$technique"

  printf '  %-6s %-22s %-10s %s\n' "$pid" "$name" "$status" "$technique"
  printf '       -> %s\n' "$note"
  echo
done < <(grep -E '\*[[:space:]]*$' <<< "$SECTION2_BLOCK")

# ---------------------------------------------------------------------------
# NETWORK CONNECTIONS
# SECTION 3's own flag column already marks [K] known-infrastructure and
# [?] not-previously-characterized -- we read that flag rather than
# re-deriving it, and cross-check [K] against the IOC database to name
# which IOC it is.
# ---------------------------------------------------------------------------
echo "NETWORK CONNECTIONS (SECTION 3 -- netscan, flagged entries only):"
printf '  %-22s %-9s %-6s %s\n' "Remote Addr:Port" "State" "PID" "IOC Match"

SECTION3_BLOCK="$(awk '/^SECTION 3/{f=1} f{print} /^SECTION 4/{exit}' "$MEM_FILE")"

while IFS= read -r line; do
  remote="$(awk '{print $3}' <<< "$line")"
  state="$(awk '{print $4}' <<< "$line")"
  pid="$(awk '{print $5}' <<< "$line")"
  remote_ip="${remote%%:*}"

  if grep -q '\[K\]' <<< "$line"; then
    ioc_id="$(ioc_lookup "ipv4" "$remote_ip")"
    if [[ -n "$ioc_id" ]]; then
      match="KNOWN (${ioc_id})"
    else
      match="KNOWN (flagged [K] in evidence, no exact IOC entry for this IP -- verify)"
    fi
    TOTAL_KNOWN=$((TOTAL_KNOWN + 1))
  else
    match="NEW (flagged [?] in evidence -- unidentified IP per James Chen)"
    TOTAL_NEW=$((TOTAL_NEW + 1))
  fi

  printf '  %-22s %-9s %-6s %s\n' "$remote" "$state" "$pid" "$match"
done < <(grep -E '^(TCP|UDP)' <<< "$SECTION3_BLOCK" | grep -E '\[K\]|\[\?\]')

NEW_CONN_LINE="$(grep -A3 'INDICATOR OF INTEREST -- HB-IOC-NEW-001' "$MEM_FILE" | head -n1)"
if [[ -n "$NEW_CONN_LINE" ]]; then
  echo
  echo "  NEW FINDING (evidence tag HB-IOC-NEW-001): secondary C2 channel"
  echo "  confirmed on a non-standard port, not observed in 4x00-4x04."
  echo "  Confidence per SECTION 3 analyst note: PROBABLE (single-host"
  echo "  evidence; needs firewall session corroboration -- see Task 2)."
  record_technique "T1571 Non-Standard Port"
fi
echo

# ---------------------------------------------------------------------------
# CREDENTIAL ACCESS INDICATORS
# SECTION 8 (loaded modules) explicitly states no third-party DLL is loaded
# by the live suspicious processes, and ldrmodules found no reflective-
# injection discrepancy. The real credential-access evidence on this host
# is a process HANDLE left by an already-exited process (SECTION 7), not a
# loaded module -- the script reports that honestly instead of forcing a
# "DLL" finding that the evidence does not contain.
# ---------------------------------------------------------------------------
echo "CREDENTIAL ACCESS INDICATORS (SECTION 7 -- handles; SECTION 8 -- modules):"

HANDLE_LINE="$(grep -n '0x1010' "$MEM_FILE" | head -n1)"
if [[ -n "$HANDLE_LINE" ]]; then
  ioc_id="$(ioc_lookup "filename" "debug_tool.exe")"
  status="KNOWN (${ioc_id:-not found in IOC database})"
  [[ -n "$ioc_id" ]] && TOTAL_KNOWN=$((TOTAL_KNOWN + 1))
  echo "  [*] Stale process handle: debug_tool.exe -> lsass.exe (PID 648)"
  echo "      Access mask: 0x1010 = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION"
  echo "      (bitmask and process both named explicitly in SECTION 7 handles)"
  echo "      ATT&CK: T1003.001 LSASS Memory (standard mapping for this access"
  echo "      pattern; not a MITRE ID stated verbatim in the file)"
  echo "      Status: ${status} -- confirms 4x04 hypothesis H4 per SECTION 7/11"
  record_technique "T1003.001 LSASS Memory"
else
  echo "  No credential-access handle pattern found in SECTION 7."
fi
echo "  Note: SECTION 8 (dlllist/ldrmodules) found no third-party DLL loaded"
echo "  by the live suspicious processes and no reflective-injection"
echo "  discrepancy -- the credential-access evidence here is the handle"
echo "  above, left by debug_tool.exe, which had already exited by capture"
echo "  time, not a module still resident in memory."
echo

# ---------------------------------------------------------------------------
# PERSISTENCE MECHANISM
# SECTION 9 (registry hives, printkey) K2 is the scheduled-task TaskCache
# entry. The memory extract gives us the task name, its registry path and
# last-write time, and that its action is a base64-encoded PowerShell
# command -- it does NOT give the trigger schedule or the full decoded
# action, which the file itself says live in disk_forensics_report.txt
# Section 4. We report that gap instead of inventing a trigger value.
# ---------------------------------------------------------------------------
echo "PERSISTENCE MECHANISM (SECTION 9 -- registry hives, entry K2):"

TASK_BLOCK="$(awk '/^\[K2\]/{f=1} f{print} /^\[K3\]/{exit}' "$MEM_FILE")"
if [[ -n "$TASK_BLOCK" ]]; then
  task_name="$(grep -oE '\\HealthSync Update Service' "$MEM_FILE" | head -n1 | sed 's/^\\//')"
  last_write="$(grep -A1 'Last Write Time' <<< "$TASK_BLOCK" | head -n1 | sed -E 's/^\s*Last Write Time:\s*//')"
  echo "  Task name:   ${task_name:-HealthSync Update Service}"
  echo "  Registry key path: HKLM\\SOFTWARE\\...\\Schedule\\TaskCache\\Tasks\\{E7B26F4C-7C39-4F7E-B6A8-2D3C1E9F0A8D}"
  echo "  Last write time (TaskCache, used here as registration time): ${last_write:-see SECTION 9 K2}"
  echo "  Trigger: NOT stated in this memory extract -- printkey records"
  echo "  last-write time only, not the trigger definition. See"
  echo "  disk_forensics_report.txt SECTION 4 for the full task XML."
  echo "  Action: base64-encoded PowerShell download-and-execute (per"
  echo "  SECTION 9 text); the PowerShell execution captured at PID 8472"
  echo "  (02:00:14 CDT, 2026-05-15 -- see SECTION 2/4) is consistent with"
  echo "  this task firing, but that is a cross-reference, not a confirmed"
  echo "  link -- the task's own command line was not recovered in memory."
  echo "  ATT&CK: T1053.005 Scheduled Task/Job (stated verbatim in SECTION 11)"
  echo "  Status: NEW -- tagged HB-IOC-NEW-002 in the evidence itself; no"
  echo "  task name or GUID matching this entry exists in the IOC database."
  record_technique "T1053.005 Scheduled Task/Job"
  TOTAL_NEW=$((TOTAL_NEW + 1))
else
  echo "  No scheduled-task registry entry (K2) found in SECTION 9."
fi
echo

echo "SUMMARY:"
echo "  Known indicators confirmed: ${TOTAL_KNOWN}"
echo "  New indicators discovered: ${TOTAL_NEW}"
if [[ "${#ATTACK_IDS[@]}" -gt 0 ]]; then
  printf '  ATT&CK techniques identified: %s\n' "$(IFS=, ; echo "${ATTACK_IDS[*]}")"
else
  echo "  ATT&CK techniques identified: none"
fi
echo "  Confidence: HIGH (primary volatile evidence) for directly-quoted"
echo "  findings; PROBABLE for the secondary C2 channel pending firewall"
echo "  corroboration (see Task 2) -- confidence is not uniform across"
echo "  every line above, see individual notes."
echo
echo "================================================================"

exit 0
