#!/bin/bash
#
# 16-lynis_diff.sh
#
# Compares pre- and post-hardening Lynis findings, producing the
# structured improvement report Sarah Park uses to see exactly which
# findings disappeared, which remain, and whether hardening introduced
# anything new.
#
# FILENAME COLLISION, disclosed directly: this project's own Task 14
# orchestrator also writes hardening_improvement.json, but with a
# different, narrower schema (before/after score plus step counts).
# This script's version, run standalone or after Task 14, is the
# richer, finding-level report the task itself specifies and is meant
# to be the authoritative hardening_improvement.json going forward;
# running this script after the orchestrator intentionally replaces
# its simpler placeholder with this fuller report.
#
# This script is idempotent: given the same two input files, it always
# regenerates the same comparison; it does not accumulate state.
 
set -euo pipefail
# Every command below that can legitimately find nothing (comm with an
# empty set, grep with no match) is guarded with "|| true", matching
# this project's established discipline for scripts with real -e.
 
BEFORE_FILE="./lynis_findings.json"
AFTER_FILE="./lynis_post_findings.json"
IMPROVEMENT_LOG="./hardening_improvement.json"
LYNIS_REPORT="/var/log/lynis-report.dat"
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since generating" >&2
  echo "a fresh post-hardening Lynis scan (if needed) requires it." >&2
  exit 1
fi
 
if [ ! -f "$BEFORE_FILE" ]; then
  echo "ERROR: ${BEFORE_FILE} not found. Run 2-lynis_parse.sh first to" >&2
  echo "produce the pre-hardening baseline." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# GENERATE lynis_post_findings.json IF IT DOES NOT ALREADY EXIST
# ---------------------------------------------------------------------
if [ ! -f "$AFTER_FILE" ]; then
  echo "[*] ${AFTER_FILE} not found, running a fresh Lynis scan..."
  if ! command -v lynis >/dev/null 2>&1; then
    apt-get install -y lynis >/tmp/lynis_install.$$ 2>&1 || true
    rm -f /tmp/lynis_install.$$
  fi
  if command -v lynis >/dev/null 2>&1; then
    lynis audit system --quick >/tmp/lynis_scan_out.$$ 2>&1 || true
    rm -f /tmp/lynis_scan_out.$$
  fi
  if [ -f "$LYNIS_REPORT" ] && [ -x "./2-lynis_parse.sh" ]; then
    ./2-lynis_parse.sh "$LYNIS_REPORT" > "$AFTER_FILE" 2>/dev/null || echo '{"hardening_index":null,"findings":[]}' > "$AFTER_FILE"
  else
    echo '{"hardening_index":null,"findings":[]}' > "$AFTER_FILE"
  fi
fi
 
# ---------------------------------------------------------------------
# JSON ESCAPE HELPER
# ---------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}
 
# ---------------------------------------------------------------------
# READ HELPERS: jq if available, portable grep-based fallback if not,
# matching this project's established resilience pattern (Task 2).
# ---------------------------------------------------------------------
read_score() {
  local file="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.hardening_index // "unknown"' "$file" 2>/dev/null || echo "unknown"
  else
    grep -oE '"hardening_index"[[:space:]]*:[[:space:]]*[0-9]+' "$file" 2>/dev/null \
      | grep -oE '[0-9]+' | head -1 || echo "unknown"
  fi
  [ -s "$file" ] || echo "unknown"
}
 
extract_ids() {
  local file="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.findings[].test_id' "$file" 2>/dev/null | sort -u || true
  else
    { grep -oE '"test_id"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" 2>/dev/null \
      | sed -E 's/.*"([^"]+)"$/\1/' | sort -u ; } || true
  fi
}
 
# Given a test_id, returns "severity|escaped_message" for its first
# matching entry in the given file.
lookup_finding() {
  local file="$1" id="$2"
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg id "$id" '.findings[] | select(.test_id==$id) | "\(.severity)|\(.message)"' "$file" 2>/dev/null | head -1
  else
    python3 -c "
import json, sys
try:
    with open('${file}') as f:
        data = json.load(f)
    for finding in data.get('findings', []):
        if finding.get('test_id') == '${id}':
            print(f\"{finding.get('severity','unknown')}|{finding.get('message','')}\")
            break
except Exception:
    pass
" 2>/dev/null
  fi
}
 
# ---------------------------------------------------------------------
# COMPUTE SCORES
# ---------------------------------------------------------------------
BEFORE_SCORE=$(read_score "$BEFORE_FILE" | head -1)
AFTER_SCORE=$(read_score "$AFTER_FILE" | head -1)
 
DELTA="unknown"
if [[ "$BEFORE_SCORE" =~ ^[0-9]+$ ]] && [[ "$AFTER_SCORE" =~ ^[0-9]+$ ]]; then
  DELTA=$((AFTER_SCORE - BEFORE_SCORE))
fi
 
# ---------------------------------------------------------------------
# COMPUTE THE THREE SETS (resolved / remaining / new) BY test_id
# ---------------------------------------------------------------------
BEFORE_IDS=$(extract_ids "$BEFORE_FILE")
AFTER_IDS=$(extract_ids "$AFTER_FILE")
 
RESOLVED_IDS=$(comm -23 <(printf '%s\n' "$BEFORE_IDS") <(printf '%s\n' "$AFTER_IDS") 2>/dev/null || true)
REMAINING_IDS=$(comm -12 <(printf '%s\n' "$BEFORE_IDS") <(printf '%s\n' "$AFTER_IDS") 2>/dev/null || true)
NEW_IDS=$(comm -13 <(printf '%s\n' "$BEFORE_IDS") <(printf '%s\n' "$AFTER_IDS") 2>/dev/null || true)
 
RESOLVED_COUNT=$(printf '%s\n' "$RESOLVED_IDS" | grep -c . || true)
REMAINING_COUNT=$(printf '%s\n' "$REMAINING_IDS" | grep -c . || true)
NEW_COUNT=$(printf '%s\n' "$NEW_IDS" | grep -c . || true)
 
# ---------------------------------------------------------------------
# BUILD JSON ARRAYS FOR EACH CATEGORY
# ---------------------------------------------------------------------
build_findings_array() {
  local ids="$1" lookup_file="$2"
  local first=true
  printf '['
  while IFS= read -r id; do
    [ -z "$id" ] && continue
    local record sev msg
    record=$(lookup_finding "$lookup_file" "$id")
    sev="${record%%|*}"
    msg="${record#*|}"
    [ -z "$sev" ] && sev="unknown"
    [ "$msg" = "$record" ] && msg=""
    if [ "$first" = true ]; then first=false; else printf ','; fi
    printf '{"test_id":"%s","severity":"%s","message":"%s"}' \
      "$(json_escape "$id")" "$(json_escape "$sev")" "$(json_escape "$msg")"
  done <<< "$ids"
  printf ']'
}
 
RESOLVED_JSON=$(build_findings_array "$RESOLVED_IDS" "$BEFORE_FILE")
REMAINING_JSON=$(build_findings_array "$REMAINING_IDS" "$AFTER_FILE")
NEW_JSON=$(build_findings_array "$NEW_IDS" "$AFTER_FILE")
 
# ---------------------------------------------------------------------
# RESIDUAL RISK SUMMARY: severity breakdown of what is still open
# ---------------------------------------------------------------------
REMAINING_WARNING=0
REMAINING_SUGGESTION=0
REMAINING_MANUAL=0
while IFS= read -r id; do
  [ -z "$id" ] && continue
  record=$(lookup_finding "$AFTER_FILE" "$id")
  sev="${record%%|*}"
  case "$sev" in
    warning) REMAINING_WARNING=$((REMAINING_WARNING + 1)) ;;
    suggestion) REMAINING_SUGGESTION=$((REMAINING_SUGGESTION + 1)) ;;
    manual_check) REMAINING_MANUAL=$((REMAINING_MANUAL + 1)) ;;
  esac
done <<< "$REMAINING_IDS"
 
RESIDUAL_SUMMARY="Of ${REMAINING_COUNT} remaining findings: ${REMAINING_WARNING} warning(s), ${REMAINING_SUGGESTION} suggestion(s), ${REMAINING_MANUAL} manual check(s) still require review."
 
# ---------------------------------------------------------------------
# WRITE hardening_improvement.json
# ---------------------------------------------------------------------
cat > "$IMPROVEMENT_LOG" <<EOF
{
  "before_score": "${BEFORE_SCORE}",
  "after_score": "${AFTER_SCORE}",
  "delta": "${DELTA}",
  "resolved_findings": ${RESOLVED_JSON},
  "remaining_findings": ${REMAINING_JSON},
  "new_findings": ${NEW_JSON},
  "resolved_count": ${RESOLVED_COUNT},
  "remaining_count": ${REMAINING_COUNT},
  "new_count": ${NEW_COUNT},
  "residual_risk_summary": "$(json_escape "$RESIDUAL_SUMMARY")"
}
EOF
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "Before: ${BEFORE_SCORE}"
echo "After: ${AFTER_SCORE}"
if [ "$DELTA" != "unknown" ] && [ "$DELTA" -ge 0 ] 2>/dev/null; then
  echo "Delta: +${DELTA}"
else
  echo "Delta: ${DELTA}"
fi
echo "Findings resolved: ${RESOLVED_COUNT}"
echo "Findings remaining: ${REMAINING_COUNT}"
echo "New findings: ${NEW_COUNT}"
echo "Report saved to: ${IMPROVEMENT_LOG}"
