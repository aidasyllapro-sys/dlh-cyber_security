#!/bin/bash
#
# script name : 15-compliance_report.sh
# purpose     : generate the patch compliance artifact - the single
#               machine-readable document answering "where are we, right
#               now, with respect to every known CVE on this host".
#               Reads vulnerability_inventory.json (current and any
#               rotated snapshots under ./history/), patch_change_log.json,
#               hold_management.json and pipeline_run.json to classify
#               every CVE ever observed as resolved, open, deferred_held
#               (package explicitly held with a documented reason) or
#               deferred_window (still open only because the maintenance
#               window guard deferred the last pipeline run), compute a
#               resolved-critical-high compliance score against a fixed
#               95.00 target, and flag overdue high/critical items open
#               more than 7 days. Emits patch_compliance.json.
# author      : Aïda Sylla
# date        : 2026-08-14
 
set -uo pipefail
# NOTE: deliberately not using -e. An open or overdue CVE, or a score
# below target, are expected, meaningful outcomes this script exists to
# report - not script bugs.
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULN_PATH="${SCRIPT_DIR}/vulnerability_inventory.json"
HISTORY_DIR="${SCRIPT_DIR}/history"
CHANGE_LOG_PATH="${SCRIPT_DIR}/patch_change_log.json"
HOLD_MGMT_PATH="${SCRIPT_DIR}/hold_management.json"
PIPELINE_RUN_PATH="${SCRIPT_DIR}/pipeline_run.json"
OUTPUT_PATH="${SCRIPT_DIR}/patch_compliance.json"
TARGET_SCORE="95.00"
OVERDUE_DAYS=7
 
if [[ ! -f "${VULN_PATH}" ]]; then
    echo "vulnerability_inventory.json not found at ${VULN_PATH}. Run 0-vuln_inventory.sh first." >&2
    exit 1
fi
if ! jq empty "${VULN_PATH}" >/dev/null 2>&1; then
    echo "vulnerability_inventory.json is not valid JSON: ${VULN_PATH}" >&2
    exit 1
fi
 
# 4. "Use patch_change_log.json for the clock": the reference point for
# how long a CVE has been open is the most recent moment the change log
# itself is aware of (its own period_end), not necessarily the literal
# system clock - this anchors the overdue calculation to what the audit
# trail actually knows happened, falling back to the real current time
# only if patch_change_log.json is unavailable or unparseable.
CLOCK_SOURCE="system clock"
if [[ -f "${CHANGE_LOG_PATH}" ]] && jq empty "${CHANGE_LOG_PATH}" >/dev/null 2>&1; then
    period_end="$(jq -r '.period_end // empty' "${CHANGE_LOG_PATH}" 2>/dev/null)"
    if [[ -n "${period_end}" ]]; then
        clock_epoch="$(date -d "${period_end}" +%s 2>/dev/null || echo "")"
        if [[ -n "${clock_epoch}" ]]; then
            CLOCK_SOURCE="patch_change_log.json (period_end: ${period_end})"
        fi
    fi
fi
echo "[*] Overdue clock reference: ${CLOCK_SOURCE}"
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
if [[ -n "${clock_epoch:-}" ]]; then
    now_epoch="${clock_epoch}"
else
    now_epoch="$(date -u +%s)"
fi
 
# ---------------------------------------------------------------------------
# 1/2. Collect every vulnerability_inventory.json snapshot (current +
#      rotated history), oldest first, and build a per-CVE presence
#      timeline across all of them.
# ---------------------------------------------------------------------------
echo "[*] Collecting vulnerability_inventory.json snapshots..."
 
SNAPSHOT_FILES=()
if [[ -d "${HISTORY_DIR}" ]]; then
    mapfile -t hist_files < <(find "${HISTORY_DIR}" -maxdepth 1 -name '*.json' 2>/dev/null | sort)
    SNAPSHOT_FILES+=("${hist_files[@]}")
else
    echo "    (no ./history/ directory - only the current snapshot is available; resolved-CVE detection will be limited to what a single point-in-time snapshot can show)" >&2
fi
SNAPSHOT_FILES+=("${VULN_PATH}")
 
echo "    ${#SNAPSHOT_FILES[@]} snapshot(s) found (including current)."
 
# CVE_LINES: one line per (cve, package, severity, snapshot_timestamp,
# snapshot_index) observation, across every snapshot.
CVE_LINES="$(mktemp)"
snapshot_idx=0
LATEST_SNAPSHOT_TS=""
for snap in "${SNAPSHOT_FILES[@]}"; do
    [[ ! -f "${snap}" ]] && continue
    jq -e empty "${snap}" >/dev/null 2>&1 || continue
    snap_ts="$(jq -r '.generated // .timestamp // empty' "${snap}" 2>/dev/null)"
    [[ -z "${snap_ts}" ]] && snap_ts="$(date -u -r "${snap}" -Iseconds 2>/dev/null || echo "")"
    [[ "${snap}" == "${VULN_PATH}" ]] && LATEST_SNAPSHOT_TS="${snap_ts}"
 
    jq -r --arg ts "${snap_ts}" --argjson idx "${snapshot_idx}" '
        .packages[]? as $p |
        ($p.cves // [])[] as $cve |
        [$cve, $p.package, ($p.severity // "unknown"), $ts, ($idx|tostring)] | @tsv
    ' "${snap}" 2>/dev/null >> "${CVE_LINES}"
 
    snapshot_idx=$((snapshot_idx + 1))
done
last_snapshot_idx=$((snapshot_idx - 1))
 
if [[ ! -s "${CVE_LINES}" ]]; then
    echo "    No CVEs found across any snapshot."
fi
 
# ---------------------------------------------------------------------------
# Load hold_management.json (currently held packages + reasons).
# ---------------------------------------------------------------------------
declare -A HELD_REASON
if [[ -f "${HOLD_MGMT_PATH}" ]] && jq empty "${HOLD_MGMT_PATH}" >/dev/null 2>&1; then
    while IFS=$'\t' read -r pkg reason; do
        [[ -z "${pkg}" ]] && continue
        HELD_REASON["${pkg}"]="${reason}"
    done < <(jq -r '.applied[]? | select(.hold_applied == true) | [.package, .reason] | @tsv' "${HOLD_MGMT_PATH}" 2>/dev/null)
fi
 
# ---------------------------------------------------------------------------
# Load pipeline_run.json status (was the most recent run deferred by the
# maintenance window guard?).
# ---------------------------------------------------------------------------
pipeline_was_deferred="false"
if [[ -f "${PIPELINE_RUN_PATH}" ]] && jq empty "${PIPELINE_RUN_PATH}" >/dev/null 2>&1; then
    status="$(jq -r '.pipeline_status // empty' "${PIPELINE_RUN_PATH}" 2>/dev/null)"
    [[ "${status}" == "deferred" ]] && pipeline_was_deferred="true"
fi
 
# patch_plan.json's own package list, so "deferred_window" is only applied
# to CVEs whose package was actually part of the plan that got deferred -
# NOT a blanket excuse for every currently-open CVE just because some
# pipeline run somewhere was deferred. A CVE whose package isn't even in
# the latest plan stays "open" (arguably more concerning, not less).
declare -A PLANNED_PACKAGES
PLAN_PATH="${SCRIPT_DIR}/patch_plan.json"
if [[ -f "${PLAN_PATH}" ]] && jq empty "${PLAN_PATH}" >/dev/null 2>&1; then
    while IFS= read -r pkg; do
        [[ -n "${pkg}" ]] && PLANNED_PACKAGES["${pkg}"]=1
    done < <(jq -r '.plan[]?.package // empty' "${PLAN_PATH}" 2>/dev/null)
fi
 
# ---------------------------------------------------------------------------
# 2 (cont). Classify every unique CVE.
# ---------------------------------------------------------------------------
echo "[*] Classifying CVE states..."
 
mapfile -t UNIQUE_CVES < <(cut -f1 "${CVE_LINES}" 2>/dev/null | sort -u)
 
CVES_JSON_ENTRIES=()
resolved_count=0
open_count=0
deferred_held_count=0
deferred_window_count=0
overdue_count=0
total_critical_high=0
resolved_critical_high=0
 
for cve in "${UNIQUE_CVES[@]}"; do
    [[ -z "${cve}" ]] && continue
 
    mapfile -t cve_rows < <(awk -F'\t' -v c="${cve}" '$1==c' "${CVE_LINES}")
 
    # Package + severity: take from the row with the highest snapshot
    # index (most recent observation) - severity/package are expected to
    # be stable for a given CVE, but if they ever changed, prefer the
    # latest.
    latest_row="$(printf '%s\n' "${cve_rows[@]}" | sort -t$'\t' -k5,5n | tail -1)"
    package="$(cut -f2 <<< "${latest_row}")"
    severity="$(cut -f3 <<< "${latest_row}")"
 
    # first_seen: earliest snapshot timestamp among all observations.
    first_seen="$(printf '%s\n' "${cve_rows[@]}" | sort -t$'\t' -k5,5n | head -1 | cut -f4)"
 
    # Was this CVE present in the CURRENT (latest) snapshot?
    currently_present="false"
    while IFS=$'\t' read -r _ _ _ _ idx; do
        [[ "${idx}" == "${last_snapshot_idx}" ]] && currently_present="true"
    done < <(printf '%s\n' "${cve_rows[@]}")
 
    resolved_at="null"
    justification="null"
 
    if [[ "${currently_present}" == "false" ]]; then
        state="resolved"
        resolved_count=$((resolved_count + 1))
        # Best available marker: the current snapshot's own timestamp,
        # since that is the point at which we confirmed the CVE was no
        # longer present - the exact moment of resolution within that
        # gap cannot be pinpointed from inventory snapshots alone.
        resolved_at="\"$(json_escape "${LATEST_SNAPSHOT_TS}")\""
    else
        held_reason="${HELD_REASON[${package}]:-}"
        if [[ -n "${held_reason}" ]]; then
            state="deferred_held"
            deferred_held_count=$((deferred_held_count + 1))
            justification="\"$(json_escape "${held_reason}")\""
        elif [[ "${pipeline_was_deferred}" == "true" && -n "${PLANNED_PACKAGES[${package}]:-}" ]]; then
            state="deferred_window"
            deferred_window_count=$((deferred_window_count + 1))
            justification="\"blocked by maintenance window guard - most recent pipeline run was deferred (pipeline_run.json)\""
        else
            state="open"
            open_count=$((open_count + 1))
        fi
    fi
 
    if [[ "${severity}" == "critical" || "${severity}" == "high" ]]; then
        total_critical_high=$((total_critical_high + 1))
        [[ "${state}" == "resolved" ]] && resolved_critical_high=$((resolved_critical_high + 1))
    fi
 
    if [[ "${state}" == "open" && ( "${severity}" == "critical" || "${severity}" == "high" ) ]]; then
        first_seen_epoch="$(date -d "${first_seen}" +%s 2>/dev/null || echo "")"
        if [[ -n "${first_seen_epoch}" ]]; then
            age_days=$(( (now_epoch - first_seen_epoch) / 86400 ))
            if [[ "${age_days}" -gt "${OVERDUE_DAYS}" ]]; then
                overdue_count=$((overdue_count + 1))
            fi
        fi
    fi
 
    CVES_JSON_ENTRIES+=("$(jq -n \
        --arg id "${cve}" --arg pkg "${package}" --arg sev "${severity}" --arg state "${state}" \
        --arg first_seen "${first_seen}" --argjson resolved_at "${resolved_at}" --argjson justification "${justification}" \
        '{id: $id, package: $pkg, severity: $sev, state: $state, first_seen: $first_seen, resolved_at: $resolved_at, justification: $justification}')")
done
 
rm -f "${CVE_LINES}"
 
# ---------------------------------------------------------------------------
# 3. Compliance score.
# ---------------------------------------------------------------------------
if [[ "${total_critical_high}" -gt 0 ]]; then
    score="$(awk -v r="${resolved_critical_high}" -v t="${total_critical_high}" 'BEGIN{printf "%.2f", (r/t)*100}')"
else
    score="100.00"
fi
 
echo "    resolved=${resolved_count} open=${open_count} deferred_held=${deferred_held_count} deferred_window=${deferred_window_count}"
echo "    score=${score}  target=${TARGET_SCORE}  overdue=${overdue_count}"
 
# ---------------------------------------------------------------------------
# 5. Emit patch_compliance.json
# ---------------------------------------------------------------------------
kernel="$(uname -r)"
CVES_JSON="[$(IFS=,; echo "${CVES_JSON_ENTRIES[*]:-}")]"
 
jq -n \
    --arg generated "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --arg kernel "${kernel}" \
    --argjson resolved "${resolved_count}" \
    --argjson open "${open_count}" \
    --argjson deferred_held "${deferred_held_count}" \
    --argjson deferred_window "${deferred_window_count}" \
    --argjson score "${score}" \
    --arg target_score "${TARGET_SCORE}" \
    --argjson overdue "${overdue_count}" \
    --argjson cves "${CVES_JSON}" \
    '{
        generated_at: $generated,
        hostname: $hostname,
        kernel: $kernel,
        summary: {
            resolved: $resolved, open: $open, deferred_held: $deferred_held, deferred_window: $deferred_window,
            score: $score, target_score: ($target_score | tonumber), overdue: $overdue
        },
        cves: $cves
    }' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
 
if awk -v s="${score}" -v t="${TARGET_SCORE}" 'BEGIN{exit !(s>=t)}'; then
    exit 0
else
    exit 1
fi
