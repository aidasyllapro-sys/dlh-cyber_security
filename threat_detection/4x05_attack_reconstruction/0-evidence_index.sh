#!/bin/bash
# 0-evidence_index.sh
# HEALTHBANE Reconstruction - Task 0: Evidence Inventory
#
# Catalogs every evidence source in ir_evidence/, previous_findings/ and
# reference/. Phase/type are derived from filename patterns, reliability
# from the source directory, and the "key content" preview and temporal
# coverage are read directly from each file's own content (not hardcoded),
# so every catalog entry is grounded in the actual evidence rather than
# in an external description of it.
set -euo pipefail

require_dir() {
  if [[ ! -d "$1" ]]; then
    echo "ERROR: required directory not found: $1" >&2
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

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IR_DIR="${BASE_DIR}/ir_evidence"
PF_DIR="${BASE_DIR}/previous_findings"
REF_DIR="${BASE_DIR}/reference"

require_dir "$IR_DIR"
require_dir "$PF_DIR"
require_dir "$REF_DIR"

HOSTNAME_VAL="$(hostname)"
DATE_VAL="$(date '+%Y-%m-%d')"

# ---------------------------------------------------------------------------
# Phase / type labels, derived from filename patterns (not a per-file table).
# Falls through to REFERENCE/REF for anything that matches no known pattern,
# which is exactly what every file in reference/ should hit.
# ---------------------------------------------------------------------------
classify() {
  local file="$1"
  case "$file" in
    *phishing*)        PHASE="4x00";    TYPE="EMAIL" ;;
    *network_timeline*) PHASE="4x01";   TYPE="NETWORK" ;;
    *attack_mapping*)  PHASE="4x02";    TYPE="INTEL" ;;
    *malware*)         PHASE="4x03";    TYPE="MALWARE" ;;
    *hunting*)         PHASE="4x04";    TYPE="SIEM" ;;
    *memory*)          PHASE="4x05-IR"; TYPE="MEMORY" ;;
    *disk*)            PHASE="4x05-IR"; TYPE="DISK" ;;
    *firewall*)        PHASE="4x05-IR"; TYPE="FIREWALL" ;;
    *notes*)           PHASE="4x05-IR"; TYPE="NOTES" ;;
    *)                 PHASE="REF";     TYPE="REFERENCE" ;;
  esac
}

type_label() {
  case "$1" in
    EMAIL)     echo "Email analysis findings" ;;
    NETWORK)   echo "Network forensics findings" ;;
    INTEL)     echo "Threat intelligence / ATT&CK mapping" ;;
    MALWARE)   echo "Malware triage findings" ;;
    SIEM)      echo "SIEM / threat hunting findings" ;;
    MEMORY)    echo "Volatile memory forensics" ;;
    DISK)      echo "Disk forensics" ;;
    FIREWALL)  echo "Firewall session logs" ;;
    NOTES)     echo "Preliminary IR observations" ;;
    *)         echo "Reference / static data" ;;
  esac
}

reliability_for() {
  local dirname="$1" type="$2"
  case "$dirname" in
    ir_evidence)
      if [[ "$type" == "NOTES" ]]; then
        echo "LOW (preliminary, some unverified)"
      else
        echo "HIGH (primary evidence, collected under controlled IR conditions)"
      fi
      ;;
    previous_findings)
      echo "MEDIUM (derived summary/report, not raw evidence)"
      ;;
    reference)
      echo "HIGH (authoritative reference data)"
      ;;
    *)
      echo "UNKNOWN"
      ;;
  esac
}

# Try to find an actual "Week N" mention in the file; empty if none found.
detect_week() {
  local f="$1"
  grep -oiE 'week[^0-9]{0,3}[0-9]+' "$f" 2>/dev/null \
    | grep -oE '[0-9]+' \
    | head -n1 || true
}

# Fallback week, used only when detect_week finds nothing in the file.
# NOTE (analyst assumption -- flagged in output, not silently used):
# inferred from the project narrative, since not every source is
# guaranteed to state its own date range in a grep-able form.
fallback_week_for_phase() {
  case "$1" in
    4x00) echo "11" ;;
    4x01) echo "11" ;;
    4x02) echo "12" ;;
    4x03) echo "13" ;;
    4x04) echo "14" ;;
    4x05-IR) echo "16" ;;
    *) echo "" ;;
  esac
}

# Content preview, read directly from the file: first line that actually
# carries alphanumeric content for text (skips blank lines AND decorative
# separator lines like "====...===="), top-level JSON keys for JSON.
# This is a citation of the file's own content, not a paraphrase of it.
preview_content() {
  local f="$1"
  if [[ "$f" == *.json ]]; then
    if jq empty "$f" > /dev/null 2>&1; then
      jq -c 'if type == "object" then keys elif type == "array" then (.[0] // {} | keys) else . end' "$f" 2>/dev/null
    else
      echo "(invalid/unparseable JSON)"
    fi
  else
    grep -m1 -E '[A-Za-z0-9]' "$f" 2>/dev/null | sed -E 's/^[[:space:]]+//' || echo "(empty file)"
  fi
}

echo "================================================================"
echo "   EVIDENCE INVENTORY - HEALTHBANE Reconstruction"
echo "   Analyst: ${HOSTNAME_VAL}    Date: ${DATE_VAL}"
echo "================================================================"
echo
echo "SOURCE CATALOG:"

declare -A WEEK_SEEN
declare -A PHASE_SOURCE_COUNT
idx=0

for dirpath in "$PF_DIR" "$IR_DIR" "$REF_DIR"; do
  dirname="$(basename "$dirpath")"
  for fullpath in "$dirpath"/*; do
    [[ -f "$fullpath" ]] || continue
    idx=$((idx + 1))
    filename="$(basename "$fullpath")"

    classify "$filename"
    reliability="$(reliability_for "$dirname" "$TYPE")"
    label="$(type_label "$TYPE")"

    week="$(detect_week "$fullpath")"
    week_tag="(detected in file)"
    if [[ -z "$week" ]]; then
      week="$(fallback_week_for_phase "$PHASE")"
      week_tag="(assumed from project narrative -- verify)"
    fi

    content_preview="$(preview_content "$fullpath")"
    linecount="$(grep -c '' "$fullpath" 2>/dev/null || echo 0)"

    printf '  [%02d] %s\n' "$idx" "$filename"
    printf '       Phase: %s\n' "$PHASE"
    printf '       Type: %s (%s)\n' "$TYPE" "$label"
    if [[ -n "$week" ]]; then
      printf '       Coverage: Week %s %s\n' "$week" "$week_tag"
    else
      printf '       Coverage: N/A (static reference data, not time-bound)\n'
    fi
    printf '       Reliability: %s\n' "$reliability"
    printf '       Lines: %s\n' "$linecount"
    printf '       Key content (first line / JSON keys): %s\n' "$content_preview"
    echo

    if [[ -n "$week" ]]; then
      WEEK_SEEN["${week}|${TYPE}"]=1
    fi
    if [[ "$PHASE" != "REF" ]]; then
      PHASE_SOURCE_COUNT["$PHASE"]=$(( ${PHASE_SOURCE_COUNT["$PHASE"]:-0} + 1 ))
    fi
  done
done

echo "TEMPORAL COVERAGE MATRIX:"
TYPES=(EMAIL NETWORK INTEL MALWARE SIEM MEMORY DISK FIREWALL NOTES)
for ((w = 11; w <= 17; w++)); do
  line="  Week ${w}  "
  any=0
  for t in "${TYPES[@]}"; do
    if [[ -n "${WEEK_SEEN[${w}|${t}]:-}" ]]; then
      line+="[${t}]"
      any=1
    fi
  done
  if [[ "$any" -eq 0 ]]; then
    line+="[--no coverage--]"
  fi
  echo "$line"
done
echo

echo "GAP ANALYSIS:"
for ((w = 11; w <= 17; w++)); do
  any=0
  for t in "${TYPES[@]}"; do
    if [[ -n "${WEEK_SEEN[${w}|${t}]:-}" ]]; then
      any=1
    fi
  done
  if [[ "$any" -eq 0 ]]; then
    printf '  TEMPORAL GAP: no evidence coverage for Week %s -- collection limitation or genuine inactivity cannot be determined without cross-source correlation (see later tasks)\n' "$w"
  fi
done

PHASES=(4x00 4x01 4x02 4x03 4x04 4x05-IR)
for ph in "${PHASES[@]}"; do
  count="${PHASE_SOURCE_COUNT[$ph]:-0}"
  if [[ "$count" -eq 1 ]]; then
    printf '  DOMAIN GAP: attack phase %s is covered by only one evidence source -- treat as a collection limitation until corroborated\n' "$ph"
  fi
done
echo

echo "CRITICAL QUESTIONS FOR RECONSTRUCTION:"
echo "  [Q1] Does the new firewall evidence confirm or contradict the"
echo "       4x01 network timeline for WS-RECV-03 ?"
echo "  [Q2] What is the unknown IP in firewall sessions -- secondary"
echo "       C2 or unrelated traffic ?"
echo "  [Q3] Did the data staging succeed in exfiltrating patient data,"
echo "       or was it interrupted by the hunt ?"
echo "  [Q4] Are there additional persistence mechanisms beyond the"
echo "       scheduled task found on WS-RECV-03 ?"
echo "  [Q5] What ATT&CK techniques remain unmapped after integrating"
echo "       all evidence sources ?"
echo
echo "================================================================"

exit 0
