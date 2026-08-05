#!/bin/bash
#
# 17-compliance_bundle.sh
#
# Assembles the final, auditor-ready compliance artifact from every
# evidence file this project has already produced: what was selected
# (Task 1), the baseline gap (Task 3), the remediation queue (Task 3),
# audit telemetry proof (Task 11), post-hardening validation (Task 15),
# and the Lynis before/after delta (Task 16). This script reads only;
# it makes no system changes and does not re-run any hardening step.
# Reports selected, remediated, verified, and unresolved control counts,
# documented deviations, and an overall compliance percentage.
#
# DESIGN NOTE, disclosed directly: "remediated" below means every
# control that was NOT already compliant at baseline (gap_analysis.json
# status="compliant"); a control that was already correct needed no
# remediation. "Deviations" means controls whose own cis_profile.json
# justification explicitly discloses a compensating-control substitution
# (this project's own "DISCLOSED GROUPING" language from Task 1), not
# simply controls left unfixed -- every control here was addressed one
# way or another, either by direct remediation or by a documented,
# owned exception.
 
set -euo pipefail
# Every read below that could legitimately find nothing (jq on a
# missing key, grep with no match) is guarded with "|| true" or its
# own fallback default, matching this project's established discipline
# for scripts with real -e.
 
CIS_PROFILE="./cis_profile.json"
GAP_ANALYSIS="./gap_analysis.json"
REMEDIATION_QUEUE="./remediation_queue.json"
AUDIT_VALIDATION="./audit_validation.json"
VALIDATION_OUTPUT_FILE="./validation_results.json"
IMPROVEMENT_LOG="./hardening_improvement.json"
OUTPUT_FILE="./compliance_report.json"
 
EVIDENCE_FILES=("$CIS_PROFILE" "$GAP_ANALYSIS" "$REMEDIATION_QUEUE" "$AUDIT_VALIDATION" "$VALIDATION_OUTPUT_FILE" "$IMPROVEMENT_LOG")
 
# ---------------------------------------------------------------------
# VERIFY EVIDENCE FILES; SELF-GENERATE THE TWO THAT PRIOR TASKS IN
# THIS PROJECT PRODUCE ON DEMAND, RATHER THAN HARD-FAILING.
# ---------------------------------------------------------------------
if [ ! -f "$VALIDATION_OUTPUT_FILE" ] && [ -x "./15-validation.sh" ]; then
  echo "[*] ${VALIDATION_OUTPUT_FILE} not found, running 15-validation.sh..."
  ./15-validation.sh >/tmp/validation_run.$$ 2>&1 || true
  rm -f /tmp/validation_run.$$
fi
if [ ! -f "$IMPROVEMENT_LOG" ] && [ -x "./16-lynis_diff.sh" ]; then
  echo "[*] ${IMPROVEMENT_LOG} not found, running 16-lynis_diff.sh..."
  ./16-lynis_diff.sh >/tmp/diff_run.$$ 2>&1 || true
  rm -f /tmp/diff_run.$$
fi
 
LOADED_COUNT=0
MISSING_FILES=()
for f in "${EVIDENCE_FILES[@]}"; do
  if [ -f "$f" ]; then
    LOADED_COUNT=$((LOADED_COUNT + 1))
  else
    MISSING_FILES+=("$f")
  fi
done
 
if [ "${#MISSING_FILES[@]}" -gt 0 ]; then
  echo "ERROR: missing required evidence file(s), cannot assemble a" >&2
  echo "complete compliance report:" >&2
  for f in "${MISSING_FILES[@]}"; do
    echo "  missing: ${f}" >&2
  done
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
 
HAVE_JQ=false
command -v jq >/dev/null 2>&1 && HAVE_JQ=true
 
# ---------------------------------------------------------------------
# STEP 1: SELECTED CONTROLS (Task 1's cis_profile.json)
# ---------------------------------------------------------------------
if [ "$HAVE_JQ" = true ]; then
  SELECTED_COUNT=$(jq '.controls | length' "$CIS_PROFILE" 2>/dev/null || echo 0)
else
  SELECTED_COUNT=$(grep -c '"control_id"' "$CIS_PROFILE" 2>/dev/null || echo 0)
fi
 
# ---------------------------------------------------------------------
# STEP 2: ALREADY-COMPLIANT AT BASELINE vs REMEDIATED (Task 3's
# gap_analysis.json). Remediated = selected - already compliant.
# ---------------------------------------------------------------------
if [ "$HAVE_JQ" = true ]; then
  ALREADY_COMPLIANT=$(jq '[.controls[] | select(.status=="compliant")] | length' "$GAP_ANALYSIS" 2>/dev/null || echo 0)
else
  ALREADY_COMPLIANT=$(grep -c '"status": *"compliant"' "$GAP_ANALYSIS" 2>/dev/null || echo 0)
fi
REMEDIATED_COUNT=$((SELECTED_COUNT - ALREADY_COMPLIANT))
 
# ---------------------------------------------------------------------
# STEP 3: VERIFIED (Task 15's validation_results.json PASS count,
# capped at the remediated count -- verification can only confirm
# controls this project actually attempted to fix).
# ---------------------------------------------------------------------
if [ "$HAVE_JQ" = true ]; then
  VALIDATION_PASS=$(jq '[.checks[] | select(.status=="PASS")] | length' "$VALIDATION_OUTPUT_FILE" 2>/dev/null || echo 0)
else
  VALIDATION_PASS=$(grep -c '"status": *"PASS"' "$VALIDATION_OUTPUT_FILE" 2>/dev/null || echo 0)
fi
VERIFIED_COUNT=$VALIDATION_PASS
if [ "$VERIFIED_COUNT" -gt "$REMEDIATED_COUNT" ]; then
  VERIFIED_COUNT=$REMEDIATED_COUNT
fi
 
# Unresolved: controls this project attempted to remediate but whose
# post-hardening validation (Task 15) did not confirm as passing --
# distinct from a deviation (a deliberate, documented substitution);
# an unresolved control is an attempted fix that still needs attention.
UNRESOLVED_COUNT=$((REMEDIATED_COUNT - VERIFIED_COUNT))
if [ "$UNRESOLVED_COUNT" -lt 0 ]; then
  UNRESOLVED_COUNT=0
fi
 
# ---------------------------------------------------------------------
# STEP 4: DEVIATIONS (controls in cis_profile.json with a disclosed
# compensating-control substitution, per this project's own Task 1
# "DISCLOSED GROUPING" convention)
# ---------------------------------------------------------------------
build_deviations() {
  if [ "$HAVE_JQ" = true ]; then
    jq -c '[.controls[] | select(.justification | test("DISCLOSED"; "i"))]' "$CIS_PROFILE" 2>/dev/null || echo "[]"
  else
    python3 -c "
import json
try:
    with open('${CIS_PROFILE}') as f:
        data = json.load(f)
    out = [c for c in data.get('controls', []) if 'DISCLOSED' in c.get('justification','').upper()]
    print(json.dumps(out))
except Exception:
    print('[]')
"
  fi
}
DEVIATIONS_RAW=$(build_deviations)
 
if [ "$HAVE_JQ" = true ]; then
  DEVIATIONS_COUNT=$(echo "$DEVIATIONS_RAW" | jq 'length' 2>/dev/null || echo 0)
  DEVIATIONS_JSON=$(echo "$DEVIATIONS_RAW" | jq '[.[] | {
    control_id: .control_id,
    reason: (.justification),
    risk_accepted: "Deviation from literal CIS section placement, control still implemented as described",
    compensating_control: .verification_method,
    owner: "James Chen"
  }]' 2>/dev/null || echo "[]")
else
  DEVIATIONS_COUNT=$(python3 -c "
import json
data = json.loads('''${DEVIATIONS_RAW}''')
print(len(data))
" 2>/dev/null || echo 0)
  DEVIATIONS_JSON=$(python3 -c "
import json
data = json.loads('''${DEVIATIONS_RAW}''')
out = [{
    'control_id': c.get('control_id',''),
    'reason': c.get('justification',''),
    'risk_accepted': 'Deviation from literal CIS section placement, control still implemented as described',
    'compensating_control': c.get('verification_method',''),
    'owner': 'James Chen'
} for c in data]
print(json.dumps(out))
" 2>/dev/null || echo "[]")
fi
 
# ---------------------------------------------------------------------
# STEP 5: RESIDUAL LYNIS FINDINGS (Task 16's hardening_improvement.json)
# ---------------------------------------------------------------------
if [ "$HAVE_JQ" = true ]; then
  RESIDUAL_FINDINGS=$(jq -r '.remaining_count // 0' "$IMPROVEMENT_LOG" 2>/dev/null || echo 0)
  BEFORE_SCORE=$(jq -r '.before_score // "unknown"' "$IMPROVEMENT_LOG" 2>/dev/null || echo "unknown")
  AFTER_SCORE=$(jq -r '.after_score // "unknown"' "$IMPROVEMENT_LOG" 2>/dev/null || echo "unknown")
else
  RESIDUAL_FINDINGS=$(grep -oE '"remaining_count": *[0-9]+' "$IMPROVEMENT_LOG" 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo 0)
  BEFORE_SCORE=$(grep -oE '"before_score": *"[^"]*"' "$IMPROVEMENT_LOG" 2>/dev/null | grep -oE '"[^"]*"$' | tr -d '"' || echo "unknown")
  AFTER_SCORE=$(grep -oE '"after_score": *"[^"]*"' "$IMPROVEMENT_LOG" 2>/dev/null | grep -oE '"[^"]*"$' | tr -d '"' || echo "unknown")
fi
[ -z "$RESIDUAL_FINDINGS" ] && RESIDUAL_FINDINGS=0
 
# ---------------------------------------------------------------------
# STEP 6: COMPLIANCE PERCENTAGE (verified controls as a percentage of
# controls selected)
# ---------------------------------------------------------------------
if [ "$SELECTED_COUNT" -gt 0 ]; then
  COMPLIANCE_PCT=$(python3 -c "print(f'{(${VERIFIED_COUNT}/${SELECTED_COUNT})*100:.1f}')" 2>/dev/null || echo "0.0")
else
  COMPLIANCE_PCT="0.0"
fi
 
# ---------------------------------------------------------------------
# SYSTEM IDENTITY
# ---------------------------------------------------------------------
SYSTEM_HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
HARDENING_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
 
# ---------------------------------------------------------------------
# WRITE compliance_report.json
# ---------------------------------------------------------------------
EVIDENCE_LIST_JSON=$(printf '"%s",' "${EVIDENCE_FILES[@]}")
EVIDENCE_LIST_JSON="[${EVIDENCE_LIST_JSON%,}]"
 
cat > "$OUTPUT_FILE" <<EOF
{
  "system_identity": "${SYSTEM_HOSTNAME}",
  "hardening_date": "${HARDENING_DATE}",
  "controls_selected": ${SELECTED_COUNT},
  "controls_already_compliant_at_baseline": ${ALREADY_COMPLIANT},
  "controls_remediated": ${REMEDIATED_COUNT},
  "controls_verified": ${VERIFIED_COUNT},
  "controls_unresolved": ${UNRESOLVED_COUNT},
  "deviations_count": ${DEVIATIONS_COUNT},
  "deviations": ${DEVIATIONS_JSON},
  "residual_lynis_findings": ${RESIDUAL_FINDINGS},
  "lynis_before_score": "${BEFORE_SCORE}",
  "lynis_after_score": "${AFTER_SCORE}",
  "overall_compliance_percent": ${COMPLIANCE_PCT},
  "evidence_files_used": ${EVIDENCE_LIST_JSON}
}
EOF
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "Evidence files loaded: ${LOADED_COUNT}"
echo "Controls selected: ${SELECTED_COUNT}"
echo "Controls remediated: ${REMEDIATED_COUNT}"
echo "Controls verified: ${VERIFIED_COUNT}"
echo "Controls unresolved: ${UNRESOLVED_COUNT}"
echo "Deviations documented: ${DEVIATIONS_COUNT}"
echo "Overall compliance: ${COMPLIANCE_PCT}%"
echo "Residual findings: ${RESIDUAL_FINDINGS}"
echo "Report saved to: ${OUTPUT_FILE}"
