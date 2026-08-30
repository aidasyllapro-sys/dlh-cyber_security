#!/bin/bash
#
# script name : 8-validate_all.sh
# purpose     : the single command Dr. Morales asked for - read
#               target_state.json, walk every declared control,
#               dispatch on its check_type, record a pass/fail/error
#               verdict with its evidence, and produce one
#               machine-readable report deciding whether the
#               environment is ready for handoff. No human judgment,
#               no narrative, no partial credit. This script is a
#               dispatcher over the evidence T3 through T7 already
#               produced - it never re-implements a control's own logic.
# author      : Aïda Sylla
# date        : 2026-08-22
#
# EXIT CODES (documented, per this capstone's own rule):
#   0 - fail_count == 0 AND error_count == 0
#   1 - controlled failure (at least one control failed or errored)
#   2 - environment error (target_state.json missing/corrupted, or jq
#       missing) - per this capstone's own Task 2 rule: a corrupted or
#       missing target_state.json is fatal for every downstream script.
#
# check_type / check_target semantics (matches 2-target_state.sh's own
# documented convention exactly):
#   file_exists        - check_target is a file path; passes if it exists.
#   grep_match           - check_target is a file path; expected_value is
#                          a regex grepped for with `grep -E`.
#   json_field_equals    - check_target is "path/to/file.json#field.path";
#                          passes if that field equals expected_value.
#   json_field_gte        - same addressing; passes if the field is
#                          numerically >= expected_value.
#   command_exit_zero      - check_target is a literal shell command;
#                          passes if it exits 0.
 
set -uo pipefail
# NOTE: deliberately not using -e. Any individual control failing or
# erroring is an expected, meaningful outcome this script exists to
# detect and report - not a script bug.
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it and re-run." >&2
    exit 2
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_STATE_PATH="${SCRIPT_DIR}/capstone/target_state.json"
OUTPUT_PATH="${SCRIPT_DIR}/capstone/exec/validation_report.json"
mkdir -p "$(dirname "${OUTPUT_PATH}")"
 
# CONFIRMED REAL, same root cause already found and fixed in
# 2-target_state.sh: earlier capstone tasks (3-linux_harden.sh,
# 6-patch_pipeline.sh) require sudo and create this same capstone/exec/
# tree while running as root - a later, non-root run of THIS script then
# fails to write into it with a permission error a bare "> file"
# redirect swallows silently under `set -uo pipefail` (no -e), producing
# a misleading "not valid JSON" message instead of the real cause.
if [[ ! -w "$(dirname "${OUTPUT_PATH}")" ]]; then
    echo "FAILED: $(dirname "${OUTPUT_PATH}") is not writable by the current user ($(id -un))." >&2
    echo "This commonly happens if an earlier capstone task (3-linux_harden.sh, 6-patch_pipeline.sh) already created this directory tree while running as root - this script does not require root itself. Either run this script with sudo, or fix ownership: sudo chown -R \"$(id -un)\":\"$(id -gn)\" \"$(dirname "${OUTPUT_PATH}")\"" >&2
    exit 1
fi
 
# Per this capstone's own explicit rule (Task 2): a corrupted or missing
# target_state.json is fatal for every downstream script.
if [[ ! -f "${TARGET_STATE_PATH}" ]]; then
    echo "FATAL: ${TARGET_STATE_PATH} is missing. Run 2-target_state.sh first." >&2
    exit 2
fi
if ! jq empty "${TARGET_STATE_PATH}" >/dev/null 2>&1; then
    echo "FATAL: ${TARGET_STATE_PATH} is not valid JSON." >&2
    exit 2
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
# ---------------------------------------------------------------------------
# Resolve a "file.json#field.path" check_target into its JSON value.
# Echoes the value (raw) on success; echoes nothing and returns 1 if the
# file is missing, not valid JSON, or the field path doesn't resolve.
# ---------------------------------------------------------------------------
resolve_json_field() {
    local check_target="$1"
    local file_part="${check_target%%#*}"
    local field_part="${check_target#*#}"
 
    # Relative evidence paths are resolved against this script's own
    # directory, matching where T3-T7 actually write their artifacts.
    [[ "${file_part}" != /* ]] && file_part="${SCRIPT_DIR}/${file_part}"
 
    if [[ ! -f "${file_part}" ]]; then
        return 1
    fi
    if ! jq empty "${file_part}" >/dev/null 2>&1; then
        return 1
    fi
 
    # Build the jq filter by splitting the field path on '.' and quoting
    # each segment explicitly, so a field name that itself contains a
    # dot-adjacent character never breaks the lookup.
    local filter="."
    local IFS='.'
    local seg
    for seg in ${field_part}; do
        filter="${filter}[\"${seg}\"]"
    done
 
    local value
    value="$(jq -e "${filter}" "${file_part}" 2>/dev/null)"
    local jq_exit=$?
    if [[ "${jq_exit}" -ne 0 || "${value}" == "null" ]]; then
        return 1
    fi
    printf '%s' "${value}"
    return 0
}
 
VERDICTS=()
total=0; pass_count=0; fail_count=0; error_count=0
declare -A FAMILY_TOTAL FAMILY_PASS FAMILY_FAIL FAMILY_ERROR
 
echo "[*] Loading target_state.json..."
controls_count="$(jq '.controls | length' "${TARGET_STATE_PATH}")"
echo "    ${controls_count} controls declared."
echo "[*] Evaluating every control..."
 
mapfile -t CONTROL_IDS < <(jq -r '.controls[].id' "${TARGET_STATE_PATH}")
 
for cid in "${CONTROL_IDS[@]}"; do
    control="$(jq -c --arg id "${cid}" '.controls[] | select(.id == $id)' "${TARGET_STATE_PATH}")"
    family="$(jq -r '.family' <<< "${control}")"
    platform="$(jq -r '.platform' <<< "${control}")"
    check_type="$(jq -r '.check_type' <<< "${control}")"
    check_target="$(jq -r '.check_target' <<< "${control}")"
    expected_value_raw="$(jq -c '.expected_value' <<< "${control}")"
    expected_value="$(jq -r '.expected_value' <<< "${control}")"
    severity="$(jq -r '.severity' <<< "${control}")"
 
    total=$((total + 1))
    FAMILY_TOTAL["${family}"]=$(( ${FAMILY_TOTAL["${family}"]:-0} + 1 ))
 
    verdict="error"
    evidence=""
 
    case "${check_type}" in
        file_exists)
            resolved_target="${check_target}"
            [[ "${resolved_target}" != /* ]] && resolved_target="${SCRIPT_DIR}/${resolved_target}"
            if [[ -e "${resolved_target}" ]]; then
                verdict="pass"; evidence="${resolved_target} exists"
            else
                verdict="fail"; evidence="${resolved_target} does not exist"
            fi
            ;;
        grep_match)
            resolved_target="${check_target}"
            [[ "${resolved_target}" != /* ]] && resolved_target="${SCRIPT_DIR}/${resolved_target}"
            if [[ ! -f "${resolved_target}" ]]; then
                verdict="error"; evidence="${resolved_target} not found - cannot grep"
            else
                match_line="$(grep -E -m1 "${expected_value}" "${resolved_target}" 2>/dev/null || true)"
                if [[ -n "${match_line}" ]]; then
                    verdict="pass"; evidence="grep -E '${expected_value}' ${resolved_target} -> matched: ${match_line}"
                else
                    verdict="fail"; evidence="grep -E '${expected_value}' ${resolved_target} -> no match"
                fi
            fi
            ;;
        json_field_equals)
            if actual_value="$(resolve_json_field "${check_target}")"; then
                # Compare using jq itself so type coercion (bool/number/
                # string) matches expected_value exactly as authored.
                if jq -e --argjson a "$(jq -n --arg v "${actual_value}" '$v')" \
                    --argjson e "${expected_value_raw}" -n \
                    '(try ($a | fromjson) catch $a) as $av | $av == $e or $a == ($e | tostring)' >/dev/null 2>&1; then
                    verdict="pass"; evidence="${check_target} == ${actual_value}"
                else
                    verdict="fail"; evidence="${check_target} == ${actual_value}, expected ${expected_value}"
                fi
            else
                verdict="error"; evidence="${check_target} - evidence file missing, invalid JSON, or field not found"
            fi
            ;;
        json_field_gte)
            if actual_value="$(resolve_json_field "${check_target}")"; then
                if [[ "${actual_value}" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
                    if awk -v a="${actual_value}" -v e="${expected_value}" 'BEGIN{exit !(a >= e)}'; then
                        verdict="pass"; evidence="${check_target} == ${actual_value} >= ${expected_value}"
                    else
                        verdict="fail"; evidence="${check_target} == ${actual_value} < ${expected_value}"
                    fi
                else
                    verdict="error"; evidence="${check_target} == '${actual_value}' is not numeric"
                fi
            else
                verdict="error"; evidence="${check_target} - evidence file missing, invalid JSON, or field not found"
            fi
            ;;
        command_exit_zero)
            # CONFIRMED REAL on a live Linux host: a WIN-* control's
            # check_target is literal PowerShell syntax
            # (e.g. "(Get-Service ...).Status -eq ..."), which bash's
            # own `eval` cannot parse - it produced real syntax errors,
            # not a meaningful pass/fail. This dispatcher must genuinely
            # dispatch by platform: a "windows" control needs `pwsh`, a
            # "linux"/"network"/"both" control needs bash. If this
            # validator itself runs on a host with no pwsh available
            # (e.g. hawthorne-app-01, a Linux host, evaluating a Windows
            # control it cannot itself execute), that control correctly
            # becomes "error" - the environment genuinely cannot decide
            # it here, not a false pass or a crash.
            if [[ "${platform}" == "windows" ]]; then
                if command -v pwsh >/dev/null 2>&1; then
                    cmd_output="$(pwsh -NoProfile -NonInteractive -Command "${check_target}" 2>&1)"
                    cmd_exit=$?
                else
                    verdict="error"; evidence="platform=windows control requires pwsh to evaluate, which is not available on this host"
                    cmd_exit=""
                fi
            else
                cmd_output="$(eval "${check_target}" 2>&1)"
                cmd_exit=$?
            fi
            if [[ -n "${cmd_exit}" ]]; then
                cmd_output_short="$(head -c 200 <<< "${cmd_output}")"
                if [[ "${cmd_exit}" -eq 0 ]]; then
                    verdict="pass"; evidence="command exited 0: ${check_target}"
                else
                    verdict="fail"; evidence="command exited ${cmd_exit}: ${check_target}$( [[ -n "${cmd_output_short}" ]] && echo " -> ${cmd_output_short}" )"
                fi
            fi
            ;;
        *)
            verdict="error"; evidence="unknown check_type: ${check_type}"
            ;;
    esac
 
    case "${verdict}" in
        pass)  pass_count=$((pass_count + 1));  FAMILY_PASS["${family}"]=$(( ${FAMILY_PASS["${family}"]:-0} + 1 )) ;;
        fail)  fail_count=$((fail_count + 1));  FAMILY_FAIL["${family}"]=$(( ${FAMILY_FAIL["${family}"]:-0} + 1 )) ;;
        error) error_count=$((error_count + 1)); FAMILY_ERROR["${family}"]=$(( ${FAMILY_ERROR["${family}"]:-0} + 1 )) ;;
    esac
 
    VERDICTS+=("$(jq -n --arg id "${cid}" --arg family "${family}" --arg severity "${severity}" \
        --arg check_type "${check_type}" --arg verdict "${verdict}" --arg evidence "$(json_escape "${evidence}")" \
        '{id: $id, family: $family, severity: $severity, check_type: $check_type, verdict: $verdict, evidence: $evidence}')")
done
 
pass_percentage="0.0"
if [[ "${total}" -gt 0 ]]; then
    pass_percentage="$(awk -v p="${pass_count}" -v t="${total}" 'BEGIN{printf "%.1f", (p/t)*100}')"
fi
 
# ---------------------------------------------------------------------------
# 3. Print a clean table to stdout, one row per family with totals.
# ---------------------------------------------------------------------------
echo ""
printf "%-14s %8s %8s %8s %8s\n" "FAMILY" "TOTAL" "PASS" "FAIL" "ERROR"
printf "%-14s %8s %8s %8s %8s\n" "------" "-----" "----" "----" "-----"
mapfile -t FAMILIES < <(jq -r '.controls[].family' "${TARGET_STATE_PATH}" | sort -u)
for fam in "${FAMILIES[@]}"; do
    printf "%-14s %8s %8s %8s %8s\n" "${fam}" "${FAMILY_TOTAL[${fam}]:-0}" "${FAMILY_PASS[${fam}]:-0}" "${FAMILY_FAIL[${fam}]:-0}" "${FAMILY_ERROR[${fam}]:-0}"
done
printf "%-14s %8s %8s %8s %8s\n" "------" "-----" "----" "----" "-----"
printf "%-14s %8s %8s %8s %8s\n" "TOTAL" "${total}" "${pass_count}" "${fail_count}" "${error_count}"
echo ""
echo "Pass rate: ${pass_percentage}%"
 
if [[ "${fail_count}" -gt 0 || "${error_count}" -gt 0 ]]; then
    echo ""
    echo "Failing/erroring controls:"
    for v in "${VERDICTS[@]}"; do
        vd="$(jq -r '.verdict' <<< "${v}")"
        if [[ "${vd}" != "pass" ]]; then
            jq -r '"  [\(.verdict|ascii_upcase)] \(.id) (\(.severity)) - \(.evidence)"' <<< "${v}"
        fi
    done
fi
 
# ---------------------------------------------------------------------------
# Emit validation_report.json
# ---------------------------------------------------------------------------
VERDICTS_JSON="[$(IFS=,; echo "${VERDICTS[*]:-}")]"
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson total "${total}" \
    --argjson pass_count "${pass_count}" \
    --argjson fail_count "${fail_count}" \
    --argjson error_count "${error_count}" \
    --arg pass_percentage "${pass_percentage}" \
    --argjson controls "${VERDICTS_JSON}" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        total: $total,
        pass_count: $pass_count,
        fail_count: $fail_count,
        error_count: $error_count,
        pass_percentage: ($pass_percentage | tonumber),
        controls: $controls
    }' > "${OUTPUT_PATH}"
 
if ! jq empty "${OUTPUT_PATH}" >/dev/null 2>&1; then
    echo "FAILED: ${OUTPUT_PATH} was written but is not valid JSON." >&2
    exit 1
fi
 
# Also written as capstone/validation.json (identical content), alongside
# the primary capstone/exec/validation_report.json, so downstream
# tooling expecting either filename finds a valid report.
ALT_OUTPUT_PATH="${SCRIPT_DIR}/capstone/validation.json"
cp "${OUTPUT_PATH}" "${ALT_OUTPUT_PATH}"
 
echo ""
echo "Total controls: ${total}"
echo "Report saved to: ${OUTPUT_PATH} (and capstone/validation.json)"
 
if [[ "${fail_count}" -eq 0 && "${error_count}" -eq 0 ]]; then
    echo "READY: every control passed."
    exit 0
else
    echo "NOT READY: ${fail_count} failed, ${error_count} errored." >&2
    exit 1
fi
