#!/bin/bash
#
# verify_artifacts.sh
#
# Cryptographic baseline check for the three forensic artifacts held under
# litigation hold LH-2026-0414-01 (incident IR-2026-0414-01). Run this before
# every analysis session. If any artifact fails verification, do not proceed
# with analysis on that artifact until the discrepancy is investigated and
# documented in chain_of_custody.md as a DEVIATION.
#
# Reminder (not enforced by this script, a process discipline): review
# siem_alert_export.json before starting disk analysis as the original SOC
# detection context only. Use what the disk artifact actually shows to
# confirm or refute the SIEM's indicators, not the other way around.
 
set -uo pipefail
 
# ---- Configuration ----------------------------------------------------------
# Directory holding the three artifact files. Override by running:
#   EVIDENCE_DIR=/path/to/evidence ./verify_artifacts.sh
EVIDENCE_DIR="${EVIDENCE_DIR:-.}"
 
HASHES_FILE="hashes.txt"
LOG_FILE="verification_log.txt"
ACTOR="${USER:-unknown_actor}"
 
# Artifact ID -> filename, in required order.
declare -A ARTIFACTS=(
  [ART-001]="wst-ws-031.dd"
  [ART-002]="wst-ws-031.mem"
  [ART-003]="wst-ws-017.mem"
)
ARTIFACT_ORDER=(ART-001 ART-002 ART-003)
 
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
 
# ---- Helpers ------------------------------------------------------------------
 
compute_hash() {
  # $1 = full path to file. Prints the SHA-256 hex digest only.
  sha256sum "$1" | awk '{print $1}'
}
 
log_event() {
  # $1=artifact_id  $2=result  $3=expected_hash  $4=computed_hash
  echo "${TIMESTAMP}|actor=${ACTOR}|artifact_id=${1}|result=${2}|expected=${3}|computed=${4}" >> "$LOG_FILE"
}
 
# ---- Main ------------------------------------------------------------------
 
if [[ ! -f "$HASHES_FILE" ]]; then
  # First run: no baseline exists yet. Establish one.
  echo "No baseline found. Establishing baseline in ${HASHES_FILE}..."
  : > "$HASHES_FILE"
  missing=0
 
  for id in "${ARTIFACT_ORDER[@]}"; do
    filename="${ARTIFACTS[$id]}"
    filepath="${EVIDENCE_DIR}/${filename}"
 
    if [[ ! -f "$filepath" ]]; then
      echo "[ERROR] ${id} ${filename}  not found at ${filepath}" >&2
      log_event "$id" "ERROR_FILE_NOT_FOUND" "N/A" "N/A"
      missing=1
      continue
    fi
 
    hash="$(compute_hash "$filepath")"
    echo "${id}:${filename}:${hash}" >> "$HASHES_FILE"
    echo "[BASELINE_SET] ${id} ${filename}  sha256=${hash}"
    log_event "$id" "BASELINE_SET" "$hash" "$hash"
  done
 
  if [[ "$missing" -eq 1 ]]; then
    echo "Baseline incomplete: one or more artifacts were not found. Fix paths and re-run." >&2
    exit 1
  fi
 
  echo "Baseline written to ${HASHES_FILE}. Run again to verify."
  exit 0
fi
 
# Subsequent run: verify against the existing baseline.
all_pass=true
 
for id in "${ARTIFACT_ORDER[@]}"; do
  filename="${ARTIFACTS[$id]}"
  filepath="${EVIDENCE_DIR}/${filename}"
  expected="$(grep "^${id}:" "$HASHES_FILE" | cut -d: -f3)"
 
  if [[ -z "$expected" ]]; then
    echo "[FAIL] ${id} ${filename}  no baseline entry found in ${HASHES_FILE}"
    log_event "$id" "FAIL" "MISSING_BASELINE" "N/A"
    all_pass=false
    continue
  fi
 
  if [[ ! -f "$filepath" ]]; then
    echo "[FAIL] ${id} ${filename}  file not found at ${filepath}"
    log_event "$id" "FAIL" "$expected" "FILE_NOT_FOUND"
    all_pass=false
    continue
  fi
 
  computed="$(compute_hash "$filepath")"
 
  if [[ "$computed" == "$expected" ]]; then
    echo "[PASS] ${id} ${filename}  expected=${expected} computed=${computed}"
    log_event "$id" "PASS" "$expected" "$computed"
  else
    echo "[FAIL] ${id} ${filename}  expected=${expected} computed=${computed}"
    log_event "$id" "FAIL" "$expected" "$computed"
    all_pass=false
  fi
done
 
if $all_pass; then
  echo "ALL ARTIFACTS VERIFIED"
  exit 0
else
  echo "ARTIFACT VERIFICATION FAILED" >&2
  exit 1
fi

