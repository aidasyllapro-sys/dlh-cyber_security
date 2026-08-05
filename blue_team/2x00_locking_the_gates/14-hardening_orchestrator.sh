#!/bin/bash
#
# 14-hardening_orchestrator.sh
#
# Runs the full hardening workflow in dependency order, stopping
# immediately on any failure, recording per-step timing and exit
# codes, and capturing the before/after Lynis score delta as evidence.
#
# RISK NOTE, disclosed directly: this orchestrator runs this project's
# riskiest scripts (SSH hardening, PAM hardening, firewall baseline)
# back-to-back, unattended, with no human verification checkpoint
# between them. Every individual script already has its own safety
# net (SSH's AllowUsers fix, PAM's backup/rollback, the firewall's
# lockout pre-flight check and scheduled auto-disable), but running
# them all in one unattended pass removes the manual "verify, then
# proceed" discipline used throughout this project. Test this on a
# fresh VM snapshot before running it against a production host, and
# keep local console access available for the entire run, not just
# checked at the end.
#
# This script is idempotent by composition: every step it calls is
# itself already idempotent (verified individually elsewhere in this
# project), so re-running the whole sequence reapplies the same
# end state rather than accumulating changes.
 
set -euo pipefail
# The sub-script invocation inside run_step() is wrapped in an
# if/then/else (bash exempts tested conditions from triggering -e),
# and every other command that can legitimately fail elsewhere in this
# script is already guarded with "|| true" or its own if-condition,
# matching the same discipline as this project's other hardening
# scripts (Tasks 0, 4, 5, 6, 7, 8, 9, 10, 11, 12).
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_LOG="./hardening_run.json"
IMPROVEMENT_LOG="./hardening_improvement.json"
LYNIS_REPORT="/var/log/lynis-report.dat"
 
# The 13-step sequence, in the exact dependency order the task
# specifies. Steps 1 and 2 (baseline + Lynis) are measurement, not
# hardening; the remaining 11 change system state.
STEPS=(
  "0-baseline_snapshot.sh"
  "__LYNIS_BASELINE__"
  "4-ssh_hardening.sh"
  "5-sysctl_hardening.sh"
  "6-filesystem_hardening.sh"
  "7-service_minimization.sh"
  "8-pam_hardening.sh"
  "9-apparmor_config.sh"
  "10-auditd_config.sh"
  "11-audit_coverage_test.sh"
  "12-log_config.sh"
  "13-firewall_baseline.sh"
  "15-validation.sh"
)
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since every step" >&2
  echo "it orchestrates individually requires root." >&2
  exit 1
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
# PRE-CHECKS: every referenced script must exist and be executable
# ---------------------------------------------------------------------
PRECHECK_OK=true
MISSING_SCRIPTS=()
for step in "${STEPS[@]}"; do
  [ "$step" = "__LYNIS_BASELINE__" ] && continue
  path="${SCRIPT_DIR}/${step}"
  if [ ! -f "$path" ]; then
    PRECHECK_OK=false
    MISSING_SCRIPTS+=("${step} (not found)")
  elif [ ! -x "$path" ]; then
    PRECHECK_OK=false
    MISSING_SCRIPTS+=("${step} (not executable)")
  fi
done
 
if [ "$PRECHECK_OK" = true ]; then
  echo "Pre-checks: PASS"
else
  echo "Pre-checks: FAIL"
  for m in "${MISSING_SCRIPTS[@]}"; do
    echo "  missing: ${m}" >&2
  done
  echo "Aborting before running any step." >&2
  exit 1
fi
 
STEPS_SCHEDULED=${#STEPS[@]}
STEPS_COMPLETED=0
STEPS_FAILED=0
STEP_LOG=()   # one JSON object string per step
 
# ---------------------------------------------------------------------
# LYNIS SCORE CAPTURE HELPER: runs a fresh Lynis scan, then parses it
# with this project's own 2-lynis_parse.sh to extract hardening_index.
# ---------------------------------------------------------------------
capture_lynis_score() {
  if ! command -v lynis >/dev/null 2>&1; then
    apt-get install -y lynis >/tmp/lynis_install.$$ 2>&1 || true
    rm -f /tmp/lynis_install.$$
  fi
  if command -v lynis >/dev/null 2>&1; then
    lynis audit system --quick >/tmp/lynis_scan_out.$$ 2>&1 || true
    rm -f /tmp/lynis_scan_out.$$
  fi
  if [ -f "$LYNIS_REPORT" ] && [ -x "${SCRIPT_DIR}/2-lynis_parse.sh" ]; then
    local parsed
    parsed=$("${SCRIPT_DIR}/2-lynis_parse.sh" "$LYNIS_REPORT" 2>/dev/null || echo "")
    if command -v jq >/dev/null 2>&1 && [ -n "$parsed" ]; then
      echo "$parsed" | jq -r '.hardening_index // "unknown"' 2>/dev/null || echo "unknown"
    else
      echo "$parsed" | grep -oE '"hardening_index":[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | head -1 || echo "unknown"
    fi
  else
    echo "unknown"
  fi
}
 
# ---------------------------------------------------------------------
# RUN ONE STEP: execute, time it, capture exit code, log it, and
# fail-fast (stop the whole sequence) on any non-zero exit code.
# ---------------------------------------------------------------------
BEFORE_SCORE="unknown"
AFTER_SCORE="unknown"
 
LAST_STEP_EXIT=0
 
run_step() {
  local index="$1" name="$2"
  local start_ts end_ts duration exit_code status
 
  start_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local start_epoch end_epoch
  start_epoch=$(date +%s)
 
  if [ "$name" = "__LYNIS_BASELINE__" ]; then
    BEFORE_SCORE=$(capture_lynis_score)
    exit_code=0
    name="lynis_baseline_capture"
  else
    if "${SCRIPT_DIR}/${name}" >/tmp/step_out.$$ 2>&1; then
      exit_code=0
    else
      exit_code=$?
    fi
    rm -f /tmp/step_out.$$
  fi
 
  end_epoch=$(date +%s)
  end_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  duration=$((end_epoch - start_epoch))
 
  if [ "$exit_code" -eq 0 ]; then
    status="SUCCESS"
    STEPS_COMPLETED=$((STEPS_COMPLETED + 1))
  else
    status="FAILED"
    STEPS_FAILED=$((STEPS_FAILED + 1))
  fi
 
  STEP_LOG+=("{\"step_index\":${index},\"script\":\"$(json_escape "$name")\",\"start\":\"${start_ts}\",\"end\":\"${end_ts}\",\"duration_seconds\":${duration},\"exit_code\":${exit_code},\"status\":\"${status}\"}")
 
  LAST_STEP_EXIT="$exit_code"
}
 
# ---------------------------------------------------------------------
# EXECUTE THE SEQUENCE, FAIL-FAST
# ---------------------------------------------------------------------
STEP_INDEX=0
for step in "${STEPS[@]}"; do
  STEP_INDEX=$((STEP_INDEX + 1))
  run_step "$STEP_INDEX" "$step"
  if [ "$LAST_STEP_EXIT" -ne 0 ]; then
    break
  fi
done
 
# Capture the after-score only if every step actually completed; a
# score taken mid-failure would misrepresent the run.
if [ "$STEPS_FAILED" -eq 0 ]; then
  AFTER_SCORE=$(capture_lynis_score)
fi
 
# ---------------------------------------------------------------------
# WRITE hardening_run.json
# ---------------------------------------------------------------------
{
  printf '{\n  "run_date": "%s",\n  "steps_scheduled": %d,\n  "steps_completed": %d,\n  "steps_failed": %d,\n  "steps": [\n' \
    "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$STEPS_SCHEDULED" "$STEPS_COMPLETED" "$STEPS_FAILED"
  total=${#STEP_LOG[@]}
  for i in "${!STEP_LOG[@]}"; do
    printf '    %s' "${STEP_LOG[$i]}"
    if [ "$i" -lt $((total - 1)) ]; then printf ',\n'; else printf '\n'; fi
  done
  printf '  ]\n}\n'
} > "$RUN_LOG"
 
# ---------------------------------------------------------------------
# WRITE hardening_improvement.json
# ---------------------------------------------------------------------
DELTA="unknown"
if [[ "$BEFORE_SCORE" =~ ^[0-9]+$ ]] && [[ "$AFTER_SCORE" =~ ^[0-9]+$ ]]; then
  DELTA=$((AFTER_SCORE - BEFORE_SCORE))
fi
 
cat > "$IMPROVEMENT_LOG" <<EOF
{
  "before_lynis_score": "${BEFORE_SCORE}",
  "after_lynis_score": "${AFTER_SCORE}",
  "delta": "${DELTA}",
  "steps_completed": ${STEPS_COMPLETED},
  "steps_failed": ${STEPS_FAILED}
}
EOF
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "Steps scheduled: ${STEPS_SCHEDULED}"
echo "Steps completed: ${STEPS_COMPLETED}"
echo "Steps failed: ${STEPS_FAILED}"
echo "Before Lynis score: ${BEFORE_SCORE}"
echo "After Lynis score: ${AFTER_SCORE}"
if [ "$DELTA" != "unknown" ] && [ "$DELTA" -ge 0 ] 2>/dev/null; then
  echo "Delta: +${DELTA}"
else
  echo "Delta: ${DELTA}"
fi
echo "Run log saved to: ${RUN_LOG}"
echo "Improvement saved to: ${IMPROVEMENT_LOG}"
 
if [ "$STEPS_FAILED" -gt 0 ]; then
  exit 1
fi
