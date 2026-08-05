#!/bin/bash
#
# 11-audit_coverage_test.sh
#
# Proves the 14 audit rules from Task 10 actually capture events, via
# 6 controlled, reversible tests: run a safe action, ausearch for the
# expected key, record captured/missed, clean up every test artifact.
# Tests 5-6 need coverage beyond Task 10's rules; this script adds its
# own temporary rules file (meddefense-coverage-test.rules), never
# touching Task 10's own rules file, and deletes it during cleanup.
# Idempotent: reruns create/remove the same artifacts, no accumulation.
 
set -euo pipefail
 
TEST_RULES_FILE="/etc/audit/rules.d/meddefense-coverage-test.rules"
TEST_DIR="/var/lib/meddefense-audit-test"
TEST_WRITE_FILE="${TEST_DIR}/coverage_test_file.txt"
TEST_CRON_FILE="/etc/cron.d/meddefense-coverage-test"
REPORT_FILE="./audit_validation.json"
 
RESULTS=()   # one JSON object string per test, appended in order
CAPTURED_COUNT=0
MISSED_COUNT=0
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it reads" >&2
  echo "the audit log and temporarily deploys a test audit rule." >&2
  exit 1
fi
 
if ! command -v auditctl >/dev/null 2>&1 || ! command -v ausearch >/dev/null 2>&1; then
  echo "ERROR: auditd tools not found. Run 10-auditd_config.sh first." >&2
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
# CLEANUP FUNCTION, ALSO REGISTERED VIA trap AS A SAFETY NET
# ---------------------------------------------------------------------
# Called explicitly below in normal execution order (so its output
# appears before the summary, matching this task's expected output).
# Also registered via trap EXIT so it still runs if the script exits
# early or on error; safe to call twice since every step is already
# guarded with "|| true" / existence checks.
CLEANUP_DONE=false
cleanup() {
  if [ "$CLEANUP_DONE" = true ]; then
    return
  fi
  CLEANUP_DONE=true
  echo "[*] Cleaning test artifacts..."
  rm -f "$TEST_CRON_FILE" 2>/dev/null || true
  rm -f "$TEST_WRITE_FILE" 2>/dev/null || true
  rmdir "$TEST_DIR" 2>/dev/null || true
  if [ -f "$TEST_RULES_FILE" ]; then
    rm -f "$TEST_RULES_FILE"
    augenrules --load >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
 
# ---------------------------------------------------------------------
# SET UP TEMPORARY TEST-ONLY AUDIT RULES (tests 5 and 6)
# ---------------------------------------------------------------------
mkdir -p "$TEST_DIR"
{
  echo "## Temporary, test-only rules from 11-audit_coverage_test.sh"
  echo "## Removed automatically at the end of this script's run."
  echo "-w ${TEST_DIR} -p wa -k audit_test_write"
  echo "-w /etc/cron.d/ -p wa -k cron_test"
} > "$TEST_RULES_FILE"
augenrules --load >/dev/null 2>&1 || true
 
# ---------------------------------------------------------------------
# RUN A SINGLE TEST: execute a command, wait briefly, search the audit
# log for the expected key, and record a structured result.
# ---------------------------------------------------------------------
run_test() {
  local index="$1" label="$2" key="$3" command_desc="$4"
  local ts status count excerpt
 
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  sleep 1
  local search_out
  search_out=$(ausearch -ts recent -k "$key" 2>/dev/null || true)
  count=$(printf '%s\n' "$search_out" | grep -oE 'audit\([0-9]+\.[0-9]+:[0-9]+\)' | sort -u | grep -c . || true)
 
  if [ "$count" -gt 0 ]; then
    status="CAPTURED"
    CAPTURED_COUNT=$((CAPTURED_COUNT + 1))
    excerpt=$(printf '%s\n' "$search_out" | grep -m1 '^type=SYSCALL' || printf '%s\n' "$search_out" | head -1)
  else
    status="MISSED"
    MISSED_COUNT=$((MISSED_COUNT + 1))
    excerpt="no matching event found for key ${key}"
  fi
 
  printf '[%d/6] %-38s [%s]\n' "$index" "$label" "$status"
 
  RESULTS+=("{\"test_name\":\"$(json_escape "$label")\",\"expected_audit_key\":\"$(json_escape "$key")\",\"command_executed\":\"$(json_escape "$command_desc")\",\"timestamp\":\"${ts}\",\"capture_status\":\"${status}\",\"event_count\":${count},\"excerpt\":\"$(json_escape "$excerpt")\"}")
}
 
# ---------------------------------------------------------------------
# THE 6 CONTROLLED TESTS
# ---------------------------------------------------------------------
echo "[*] Running audit telemetry coverage tests..."
 
# 1. sudo execution (already root, no real privilege change occurs)
sudo -n /usr/bin/true >/dev/null 2>&1 || /usr/bin/sudo /usr/bin/true >/dev/null 2>&1 || true
run_test 1 "sudo execution" "priv_esc" "sudo /usr/bin/true"
 
# 2. shadow metadata touch only, never reads/writes real hash content
touch /etc/shadow 2>/dev/null || true
run_test 2 "shadow access" "identity" "touch /etc/shadow"
 
# 3. --version only, no real network activity
if command -v curl >/dev/null 2>&1; then
  curl --version >/dev/null 2>&1 || true
  DL_CMD="curl --version"
elif command -v wget >/dev/null 2>&1; then
  wget --version >/dev/null 2>&1 || true
  DL_CMD="wget --version"
else
  DL_CMD="(neither curl nor wget installed)"
fi
run_test 3 "suspicious download tool" "suspicious_download" "$DL_CMD"
 
# 4. sshd_config metadata touch only
touch /etc/ssh/sshd_config 2>/dev/null || true
run_test 4 "sshd config read" "sshd_config" "touch /etc/ssh/sshd_config"
 
# 5. write under this script's own temporary monitored test path
echo "coverage test $(date -u +%s)" > "$TEST_WRITE_FILE" 2>/dev/null || true
run_test 5 "monitored test file write" "audit_test_write" "echo > ${TEST_WRITE_FILE}"
 
# 6. comment-only placeholder cron file, never a real schedule line
echo "# meddefense audit coverage test placeholder, safe to ignore" > "$TEST_CRON_FILE" 2>/dev/null || true
run_test 6 "cron configuration check" "cron_test" "create placeholder ${TEST_CRON_FILE}"
 
# ---------------------------------------------------------------------
# BUILD audit_validation.json (before cleanup, so paths referenced in
# excerpts are still meaningful; the report itself is independent of
# whether the temporary test artifacts still exist on disk)
# ---------------------------------------------------------------------
{
  printf '{\n  "run_date": "%s",\n  "tests_executed": %d,\n  "captured": %d,\n  "missed": %d,\n  "results": [\n' \
    "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "${#RESULTS[@]}" "$CAPTURED_COUNT" "$MISSED_COUNT"
  total=${#RESULTS[@]}
  for i in "${!RESULTS[@]}"; do
    printf '    %s' "${RESULTS[$i]}"
    if [ "$i" -lt $((total - 1)) ]; then printf ',\n'; else printf '\n'; fi
  done
  printf '  ]\n}\n'
} > "$REPORT_FILE"
 
# ---------------------------------------------------------------------
# CLEANUP, called explicitly here so its own output line appears in
# the correct place relative to the summary below, matching this
# task's expected output ordering. The trap above still covers early
# exit/error cases; cleanup() is idempotent, so this is safe either way.
# ---------------------------------------------------------------------
cleanup
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "Tests executed: ${#RESULTS[@]}"
echo "Captured: ${CAPTURED_COUNT}"
echo "Missed: ${MISSED_COUNT}"
echo "Report saved to: ${REPORT_FILE}"
