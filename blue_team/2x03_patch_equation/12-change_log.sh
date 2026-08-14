#!/bin/bash
#
# script name : 12-change_log.sh
# purpose     : produce the canonical, structured change log for this host
#               by parsing /var/log/apt/history.log (including rotated and
#               .gz-compressed history.log.N files), grouping individual
#               apt transactions into change events by 15-minute time
#               proximity, and enriching each event with its requesting
#               user, whether it fell inside a maintenance window (by
#               calling 11-maintenance_window.sh --report against the
#               event's own timestamp, rather than duplicating its
#               decision logic here), whether it overlaps a recorded
#               patch_execution_log.json run, and which touched packages
#               are no longer flagged vulnerable in
#               vulnerability_inventory.json. Emits patch_change_log.json.
#               Pure read-only reporting - never touches package state.
# author      : Aïda Sylla
# date        : 2026-08-14

set -uo pipefail
# NOTE: deliberately not using -e. An event outside its window, or a
# package with no resolved CVE match, are expected, meaningful outcomes
# this script exists to report - not script bugs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${SCRIPT_DIR}/patch_change_log.json"
GUARD_SCRIPT="${SCRIPT_DIR}/11-maintenance_window.sh"
EXEC_LOG_PATH="${SCRIPT_DIR}/patch_execution_log.json"
VULN_PATH="${SCRIPT_DIR}/vulnerability_inventory.json"
APT_HISTORY_GLOB="/var/log/apt/history.log*"
GROUP_GAP_SECONDS=900  # 15 minutes

if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}

# ---------------------------------------------------------------------------
# 1. Collect and parse every apt transaction from history.log and its
#    rotated siblings (plain or .gz), oldest content first isn't required
#    here since every transaction is re-sorted by timestamp afterward.
# ---------------------------------------------------------------------------
echo "[*] Parsing /var/log/apt/history.log*..."

RAW_LOG="$(mktemp)"
shopt -s nullglob
for f in ${APT_HISTORY_GLOB}; do
    if [[ "${f}" == *.gz ]]; then
        zcat "${f}" 2>/dev/null >> "${RAW_LOG}" || true
    else
        cat "${f}" 2>/dev/null >> "${RAW_LOG}" || true
    fi
    echo "" >> "${RAW_LOG}"
done
shopt -u nullglob

if [[ ! -s "${RAW_LOG}" ]]; then
    echo "No apt history log found (checked ${APT_HISTORY_GLOB}). Nothing to report." >&2
    rm -f "${RAW_LOG}"
fi

# Split into blocks on blank lines (awk RS="") and parse each block's
# fields. Transactions are written out as pipe-delimited lines:
#   start_epoch|end_epoch|commandline|requested_by|packages(comma-sep)
#
# Real apt history.log field names, as they literally appear in each
# transaction block: Upgrade: (package version bumped), Install: (new
# package added), Remove: (package deleted), Reinstall: (same version
# reinstalled). The extraction regex below matches all four via
# alternation rather than four separate literal greps.
PARSED_TXNS="$(mktemp)"
awk 'BEGIN{RS=""; FS="\n"} {print; print "---TXN-BOUNDARY---"}' "${RAW_LOG}" > "${PARSED_TXNS}.blocks"

txn_count=0
TRANSACTIONS_TSV="$(mktemp)"

current_block=""
while IFS= read -r line; do
    if [[ "${line}" == "---TXN-BOUNDARY---" ]]; then
        if [[ -n "${current_block}" ]]; then
            start_date="$(grep -m1 '^Start-Date:' <<< "${current_block}" | sed 's/^Start-Date:[[:space:]]*//')"
            if [[ -n "${start_date}" ]]; then
                end_date="$(grep -m1 '^End-Date:' <<< "${current_block}" | sed 's/^End-Date:[[:space:]]*//')"
                commandline="$(grep -m1 '^Commandline:' <<< "${current_block}" | sed 's/^Commandline:[[:space:]]*//')"
                requested_by="$(grep -m1 '^Requested-By:' <<< "${current_block}" | sed -E 's/^Requested-By:[[:space:]]*([^ (]+).*/\1/')"
                [[ -z "${requested_by}" ]] && requested_by="root"

                pkgs="$(grep -E '^(Upgrade|Install|Remove|Reinstall):' <<< "${current_block}" \
                    | sed -E 's/^(Upgrade|Install|Remove|Reinstall):[[:space:]]*//' \
                    | grep -oP '[A-Za-z0-9.+_-]+(?=:\S+ \()' \
                    | sort -u | paste -sd, -)"

                start_epoch="$(date -d "${start_date}" +%s 2>/dev/null || echo "")"
                end_epoch="$(date -d "${end_date}" +%s 2>/dev/null || echo "${start_epoch}")"

                if [[ -n "${start_epoch}" ]]; then
                    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
                        "${start_epoch}" "${end_epoch}" "$(json_escape "${commandline}")" \
                        "$(json_escape "${requested_by}")" "${pkgs}" "$(json_escape "${start_date}")" \
                        >> "${TRANSACTIONS_TSV}"
                    txn_count=$((txn_count + 1))
                fi
            fi
        fi
        current_block=""
    else
        current_block+="${line}"$'\n'
    fi
done < "${PARSED_TXNS}.blocks"

rm -f "${RAW_LOG}" "${PARSED_TXNS}.blocks"

echo "    ${txn_count} transactions parsed."

if [[ "${txn_count}" -eq 0 ]]; then
    jq -n '{period_start: null, period_end: null, events: [], summary: {total_events: 0, inside_window: 0, outside_window: 0, cves_resolved: 0}}' > "${OUTPUT_PATH}"
    echo "Report saved to: $(basename "${OUTPUT_PATH}")"
    rm -f "${TRANSACTIONS_TSV}"
    exit 0
fi

# Sort transactions by start_epoch, deterministically (idempotent output
# requires a stable, well-defined sort - numeric on field 1).
sort -t$'\t' -k1,1n "${TRANSACTIONS_TSV}" -o "${TRANSACTIONS_TSV}"

# ---------------------------------------------------------------------------
# 2. Group transactions into change events by 15-minute proximity
#    (chained: each transaction need only be within the gap of the
#    PREVIOUS transaction in sorted order to join the same event).
# ---------------------------------------------------------------------------
echo "[*] Grouping into change events (15-minute proximity)..."

declare -a GROUP_START GROUP_END GROUP_COMMANDLINES GROUP_USER GROUP_PACKAGES GROUP_STARTDATE
group_idx=-1
prev_start_epoch=""

while IFS=$'\t' read -r s_epoch e_epoch cmdline reqby pkgs startdate_disp; do
    if [[ -z "${prev_start_epoch}" || $((s_epoch - prev_start_epoch)) -gt "${GROUP_GAP_SECONDS}" ]]; then
        group_idx=$((group_idx + 1))
        GROUP_START[${group_idx}]="${s_epoch}"
        GROUP_END[${group_idx}]="${e_epoch}"
        GROUP_USER[${group_idx}]="${reqby}"
        GROUP_COMMANDLINES[${group_idx}]="${cmdline}"
        GROUP_PACKAGES[${group_idx}]="${pkgs}"
        GROUP_STARTDATE[${group_idx}]="${startdate_disp}"
    else
        [[ "${e_epoch}" -gt "${GROUP_END[${group_idx}]}" ]] && GROUP_END[${group_idx}]="${e_epoch}"
        GROUP_COMMANDLINES[${group_idx}]="${GROUP_COMMANDLINES[${group_idx}]}; ${cmdline}"
        GROUP_PACKAGES[${group_idx}]="${GROUP_PACKAGES[${group_idx}]},${pkgs}"
    fi
    prev_start_epoch="${s_epoch}"
done < "${TRANSACTIONS_TSV}"

rm -f "${TRANSACTIONS_TSV}"
event_count=$((group_idx + 1))
echo "    ${event_count} change events."

# ---------------------------------------------------------------------------
# Load patch_execution_log.json range once, if present.
# ---------------------------------------------------------------------------
HAVE_EXEC_LOG=false
exec_log_start_epoch=""
exec_log_end_epoch=""
if [[ -f "${EXEC_LOG_PATH}" ]] && jq empty "${EXEC_LOG_PATH}" >/dev/null 2>&1; then
    HAVE_EXEC_LOG=true
    exec_started_at="$(jq -r '.started_at // empty' "${EXEC_LOG_PATH}")"
    exec_finished_at="$(jq -r '.finished_at // empty' "${EXEC_LOG_PATH}")"
    [[ -n "${exec_started_at}" ]] && exec_log_start_epoch="$(date -d "${exec_started_at}" +%s 2>/dev/null || echo "")"
    [[ -n "${exec_finished_at}" ]] && exec_log_end_epoch="$(date -d "${exec_finished_at}" +%s 2>/dev/null || echo "")"
fi

HAVE_VULN=false
if [[ -f "${VULN_PATH}" ]] && jq empty "${VULN_PATH}" >/dev/null 2>&1; then
    HAVE_VULN=true
fi

# ---------------------------------------------------------------------------
# 3. Enrich each event and build the JSON.
# ---------------------------------------------------------------------------
echo "[*] Enriching events (window check, execution log link, CVE cross-reference)..."

EVENTS=()
inside_count=0
outside_count=0
total_cves_resolved=0
period_start_epoch="${GROUP_START[0]}"
period_end_epoch="${GROUP_END[0]}"

for i in $(seq 0 $((event_count - 1))); do
    s_epoch="${GROUP_START[${i}]}"
    e_epoch="${GROUP_END[${i}]}"
    [[ "${s_epoch}" -lt "${period_start_epoch}" ]] && period_start_epoch="${s_epoch}"
    [[ "${e_epoch}" -gt "${period_end_epoch}" ]] && period_end_epoch="${e_epoch}"

    started_iso="$(date -d "@${s_epoch}" -Iseconds)"
    ended_iso="$(date -d "@${e_epoch}" -Iseconds)"
    user="${GROUP_USER[${i}]}"
    IFS=',' read -r -a pkgs_array <<< "${GROUP_PACKAGES[${i}]}"
    mapfile -t pkgs_unique < <(printf '%s\n' "${pkgs_array[@]}" | grep -v '^$' | sort -u)
    pkg_count="${#pkgs_unique[@]}"

    # --- within_window: call the guard script against this event's own
    # timestamp (MW_AS_OF), rather than re-implementing its decision logic.
    within_window="unknown"
    if [[ -x "${GUARD_SCRIPT}" ]]; then
        guard_json="$(MW_AS_OF="$(date -d "@${s_epoch}" '+%Y-%m-%d %H:%M:%S')" "${GUARD_SCRIPT}" --report 2>/dev/null || true)"
        if [[ -n "${guard_json}" ]]; then
            decision="$(jq -r '.decision // empty' <<< "${guard_json}" 2>/dev/null || true)"
            if [[ "${decision}" == proceed* ]]; then
                within_window="inside"
            elif [[ -n "${decision}" ]]; then
                within_window="outside"
            fi
        fi
    fi
    [[ "${within_window}" == "inside" ]] && inside_count=$((inside_count + 1))
    [[ "${within_window}" == "outside" ]] && outside_count=$((outside_count + 1))

    # --- linked_execution_log: overlap with patch_execution_log.json's
    # own recorded start/finish range.
    linked_log="null"
    if [[ "${HAVE_EXEC_LOG}" == true && -n "${exec_log_start_epoch}" && -n "${exec_log_end_epoch}" ]]; then
        if [[ "${s_epoch}" -le "${exec_log_end_epoch}" && "${e_epoch}" -ge "${exec_log_start_epoch}" ]]; then
            linked_log="\"$(json_escape "${EXEC_LOG_PATH}")\""
        fi
    fi

    # --- cves_resolved: best-effort proxy. vulnerability_inventory.json is
    # a CURRENT snapshot, not a historical archive, so the specific CVE
    # IDs a past event resolved cannot be recovered from it alone - this
    # only reports packages touched by this event that are NOT currently
    # listed as vulnerable, as a plausible (not certain) signal.
    resolved_pkgs=()
    if [[ "${HAVE_VULN}" == true ]]; then
        for pkg in "${pkgs_unique[@]}"; do
            [[ -z "${pkg}" ]] && continue
            still_flagged="$(jq -r --arg p "${pkg}" '[.packages[]? | select(.package == $p)] | length > 0' "${VULN_PATH}" 2>/dev/null || echo "true")"
            [[ "${still_flagged}" == "false" ]] && resolved_pkgs+=("${pkg}")
        done
    fi
    resolved_count="${#resolved_pkgs[@]}"
    total_cves_resolved=$((total_cves_resolved + resolved_count))

    pkgs_json="[$(for p in "${pkgs_unique[@]}"; do [[ -n "${p}" ]] && printf '"%s",' "$(json_escape "${p}")"; done | sed 's/,$//')]"
    resolved_json="[$(for p in "${resolved_pkgs[@]}"; do printf '"%s",' "$(json_escape "${p}")"; done | sed 's/,$//')]"

    event=$(jq -n \
        --arg started "${started_iso}" --arg ended "${ended_iso}" \
        --arg user "${user}" --arg within "${within_window}" \
        --argjson packages_count "${pkg_count}" --argjson packages "${pkgs_json}" \
        --argjson linked "${linked_log}" --argjson resolved "${resolved_json}" \
        --arg cmdline "${GROUP_COMMANDLINES[${i}]}" \
        '{started: $started, ended: $ended, user: $user, within_window: $within,
          packages: $packages_count, package_list: $packages, commandline: $cmdline,
          linked_execution_log: $linked, cves_resolved: $resolved}')
    EVENTS+=("${event}")
done

# ---------------------------------------------------------------------------
# 4. Emit patch_change_log.json
# ---------------------------------------------------------------------------
EVENTS_JSON="[$(IFS=,; echo "${EVENTS[*]:-}")]"

jq -n \
    --arg period_start "$(date -d "@${period_start_epoch}" -Iseconds)" \
    --arg period_end "$(date -d "@${period_end_epoch}" -Iseconds)" \
    --argjson events "${EVENTS_JSON}" \
    --argjson total_events "${event_count}" \
    --argjson inside "${inside_count}" \
    --argjson outside "${outside_count}" \
    --argjson cves_resolved "${total_cves_resolved}" \
    '{
        period_start: $period_start,
        period_end: $period_end,
        events: $events,
        summary: { total_events: $total_events, inside_window: $inside, outside_window: $outside, cves_resolved: $cves_resolved }
    }' > "${OUTPUT_PATH}"

echo "Total events: ${event_count}   Inside window: ${inside_count}   Outside window: ${outside_count}"
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
exit 0
