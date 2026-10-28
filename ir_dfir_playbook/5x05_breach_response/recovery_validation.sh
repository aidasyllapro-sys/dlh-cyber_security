#!/bin/bash
# recovery_validation.sh — IR-2026-0420-01 post-eradication validation
#
# This script is a real, runnable template meant to be executed by the response
# team against the live environment (EDR console, SIEM, DNS/firewall, and the
# clinical service endpoints). It is NOT pre-run here: this environment has no
# reachable hosts, EDR console, or SIEM — running it now would either fail on
# missing endpoints or require faking output, neither of which belongs in this
# repo. Fill in the CONFIG section below with real endpoints/credentials before
# running it against the actual environment.
#
# Exits 0 only if every check passes; exits 1 on the first failed or
# unconfirmable check, printing which one failed.

set -uo pipefail

# ---------------------------- CONFIG ----------------------------
AFFECTED_HOSTS=("CS-WS-101" "CS-WS-104" "CS-WS-107" "CS-WS-112" "FILE-SVR-01" "SCHED-SVR-01")
C2_DOMAIN="staging.office365-cdn.net"
C2_IP="45.152.66.114"
BEACON_PROCESS_NAME="svchost32.exe"
STAGING_PATTERNS=("*.bat" "*.ps1")
STAGING_DIRS=("C:\\Windows\\System32" "C:\\ProgramData")

CLINICAL_SERVICES=(
  "epic-api:https://epic-api.internal/health"
  "lis-api:https://lis-api.internal/health"
  "scheduling-api:https://scheduling-api.internal/health"
)

EDR_API="https://edr-console.internal/api/v1/hosts"
EDR_API_TOKEN="${EDR_API_TOKEN:-}"            # set via environment, never hardcode

SIEM_API="https://siem.internal/api/v1/rules"
SIEM_API_TOKEN="${SIEM_API_TOKEN:-}"          # set via environment, never hardcode
SIGMA_RULE_ID="sigma_cobalt_strike_beacon.yml"  # produced in Task 8

EVIDENCE_MANIFEST="./evidence_sha256_baseline.txt"  # "<sha256>  <path>" per line,
                                                     # sourced from evidence_preservation.md
# ------------------------------------------------------------------

FAIL=0

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAIL=1; }

# 1. No beacon process tree in the last 24 hours, across all affected hosts
check_beacon() {
  local any_found=0
  for host in "${AFFECTED_HOSTS[@]}"; do
    # Requires remote query capability (WinRM/EDR API) — placeholder invocation:
    if ! result=$(curl -sf -H "Authorization: Bearer ${EDR_API_TOKEN}" \
      "${EDR_API}/${host}/processes?since=24h&name=${BEACON_PROCESS_NAME}" 2>/dev/null); then
      fail "beacon: unable to query EDR for host ${host} — cannot confirm"
      any_found=1
      continue
    fi
    if echo "$result" | grep -qi "${BEACON_PROCESS_NAME}"; then
      fail "beacon: ${BEACON_PROCESS_NAME} process found on ${host} within last 24h"
      any_found=1
    fi
  done
  [ "$any_found" -eq 0 ] && pass "beacon: no ${BEACON_PROCESS_NAME} or related process tree in last 24h across all affected hosts"
}

# 2. No outbound connections to the C2 domain/IP
check_c2() {
  local any_found=0
  for host in "${AFFECTED_HOSTS[@]}"; do
    if ! result=$(curl -sf -H "Authorization: Bearer ${EDR_API_TOKEN}" \
      "${EDR_API}/${host}/network?since=24h&dst=${C2_IP}" 2>/dev/null); then
      fail "c2: unable to query network telemetry for host ${host} — cannot confirm"
      any_found=1
      continue
    fi
    if [ -n "$result" ] && [ "$result" != "[]" ]; then
      fail "c2: outbound connection to ${C2_DOMAIN} / ${C2_IP} found from ${host}"
      any_found=1
    fi
  done
  [ "$any_found" -eq 0 ] && pass "c2: no outbound connections to ${C2_DOMAIN} or ${C2_IP}"
}

# 3. No ransomware staging scripts in system directories
check_staging_scripts() {
  local any_found=0
  for host in "${AFFECTED_HOSTS[@]}"; do
    for dir in "${STAGING_DIRS[@]}"; do
      for pattern in "${STAGING_PATTERNS[@]}"; do
        if ! result=$(curl -sf -H "Authorization: Bearer ${EDR_API_TOKEN}" \
          "${EDR_API}/${host}/files?path=${dir}&pattern=${pattern}" 2>/dev/null); then
          fail "ransomware staging: unable to query ${host} for ${dir}\\${pattern} — cannot confirm"
          any_found=1
          continue
        fi
        if [ -n "$result" ] && [ "$result" != "[]" ]; then
          fail "ransomware staging: match for ${pattern} found in ${dir} on ${host}"
          any_found=1
        fi
      done
    done
  done
  [ "$any_found" -eq 0 ] && pass "ransomware staging: no .bat or .ps1 staging scripts found in Windows\\System32 or ProgramData"
}

# 4. All clinical service endpoints responsive
check_clinical_services() {
  local results=""
  local any_down=0
  for entry in "${CLINICAL_SERVICES[@]}"; do
    name="${entry%%:*}"
    url="${entry#*:}"
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" || echo "000")
    results="${results}${name} ${code}, "
    if [ "$code" != "200" ]; then
      any_down=1
    fi
  done
  results="${results%, }"
  if [ "$any_down" -eq 0 ]; then
    pass "services: ${results}"
  else
    fail "services: one or more endpoints not returning 200 (${results})"
  fi
}

# 5. All affected EDR agents reporting in the last 5 minutes
check_edr_reporting() {
  local any_stale=0
  for host in "${AFFECTED_HOSTS[@]}"; do
    if ! last_seen=$(curl -sf -H "Authorization: Bearer ${EDR_API_TOKEN}" \
      "${EDR_API}/${host}/last_seen" 2>/dev/null); then
      fail "edr: unable to query last-seen for ${host} — cannot confirm"
      any_stale=1
      continue
    fi
    # Expect last_seen as epoch seconds; compare to now-300s
    now=$(date +%s)
    if [ -z "$last_seen" ] || [ $(( now - last_seen )) -gt 300 ]; then
      fail "edr: ${host} has not reported to EDR console in the last 5 minutes"
      any_stale=1
    fi
  done
  [ "$any_stale" -eq 0 ] && pass "edr: all ${#AFFECTED_HOSTS[@]} hosts reporting to EDR console in last 5 minutes"
}

# 6. New Sigma rule active in the SIEM, synthetic test returns expected hit
check_sigma_rule() {
  if ! status=$(curl -sf -H "Authorization: Bearer ${SIEM_API_TOKEN}" \
    "${SIEM_API}/${SIGMA_RULE_ID}/status" 2>/dev/null); then
    fail "detection: unable to query SIEM for rule ${SIGMA_RULE_ID} — cannot confirm"
    return
  fi
  if ! echo "$status" | grep -qi '"active":true'; then
    fail "detection: ${SIGMA_RULE_ID} is not active in the SIEM"
    return
  fi
  if ! test_result=$(curl -sf -X POST -H "Authorization: Bearer ${SIEM_API_TOKEN}" \
    "${SIEM_API}/${SIGMA_RULE_ID}/test" 2>/dev/null); then
    fail "detection: synthetic test event submission failed for ${SIGMA_RULE_ID}"
    return
  fi
  if echo "$test_result" | grep -qi '"hit":true'; then
    pass "detection: ${SIGMA_RULE_ID} active; synthetic test event returned expected hit"
  else
    fail "detection: ${SIGMA_RULE_ID} active but synthetic test event did not return expected hit"
  fi
}

# 7. Evidence hashes match the original baseline
check_evidence_hashes() {
  if [ ! -f "$EVIDENCE_MANIFEST" ]; then
    fail "evidence hashes: manifest ${EVIDENCE_MANIFEST} not found — cannot confirm"
    return
  fi
  local total=0
  local matched=0
  local missing_baseline=()
  while read -r expected_hash artifact_path; do
    [ -z "$expected_hash" ] && continue
    total=$((total + 1))
    if [ "$expected_hash" = "UNHASHED" ]; then
      missing_baseline+=("$artifact_path")
      continue
    fi
    if [ -f "$artifact_path" ]; then
      actual_hash=$(sha256sum "$artifact_path" | awk '{print $1}')
      if [ "$actual_hash" = "$expected_hash" ]; then
        matched=$((matched + 1))
      fi
    fi
  done < "$EVIDENCE_MANIFEST"

  if [ ${#missing_baseline[@]} -gt 0 ]; then
    fail "evidence hashes: ${matched}/${total} verified — ${#missing_baseline[@]} artifact(s) have no baseline hash to compare against (${missing_baseline[*]}, known gap from Task 1 acquisition — see evidence_preservation.md)"
    return
  fi

  if [ "$matched" -eq "$total" ]; then
    pass "evidence hashes: ${matched}/${total} artifacts match original SHA-256 baseline"
  else
    fail "evidence hashes: only ${matched}/${total} artifacts match original SHA-256 baseline"
  fi
}

echo "Running recovery validation for IR-2026-0420-01..."
echo

check_beacon
check_c2
check_staging_scripts
check_clinical_services
check_edr_reporting
check_sigma_rule
check_evidence_hashes

echo
if [ "$FAIL" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
  exit 0
else
  echo "ONE OR MORE CHECKS FAILED — environment is not confirmed clean"
  exit 1
fi
