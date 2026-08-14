#!/bin/bash
#
# script name : 10-version_hold.sh
# purpose     : manage apt-mark holds and apt preferences pins as a
#               data-driven, declarative operation - hold_registry.json is
#               the single source of truth. For every registry entry,
#               apply apt-mark hold and write a pin fragment to
#               /etc/apt/preferences.d/meddefense-pins (regenerated fresh
#               every run, this script is the only writer); release any
#               hold currently on the system that is no longer in the
#               registry (convergence mode); compute days_to_review for
#               every entry; emit a structured hold_management.json.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -uo pipefail
# NOTE: deliberately not using -e. A hold that needs releasing, an overdue
# review, or an individual apt-mark call failing are expected, meaningful
# outcomes this script exists to report - not script bugs. Every command
# whose non-zero exit is normal control flow is handled explicitly.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it changes apt-mark state and writes to /etc/apt/preferences.d). Try: sudo $0" >&2
    exit 1
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to read the registry and write the report. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY_PATH="${SCRIPT_DIR}/hold_registry.json"
OUTPUT_PATH="${SCRIPT_DIR}/hold_management.json"
PIN_FRAGMENT_PATH="/etc/apt/preferences.d/meddefense-pins"
PIN_PRIORITY=1001
 
if [[ ! -f "${REGISTRY_PATH}" ]]; then
    echo "hold_registry.json not found at ${REGISTRY_PATH}. Nothing to converge to - refusing to touch any existing hold blindly." >&2
    exit 1
fi
if ! jq empty "${REGISTRY_PATH}" >/dev/null 2>&1; then
    echo "hold_registry.json is not valid JSON: ${REGISTRY_PATH}" >&2
    exit 1
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
registry_count="$(jq '.holds | length' "${REGISTRY_PATH}")"
echo "[*] Reading hold_registry.json...           (${registry_count} entries)"
 
mapfile -t CURRENT_HOLDS < <(apt-mark showhold 2>/dev/null | sort -u)
holds_word="entries"
[[ "${#CURRENT_HOLDS[@]}" -eq 1 ]] && holds_word="entry"
echo "[*] Reading current apt-mark showhold...    (${#CURRENT_HOLDS[@]} ${holds_word})"
 
# ---------------------------------------------------------------------------
# 2. Apply hold + pin for every registry entry.
# ---------------------------------------------------------------------------
echo "Applying holds:"
 
APPLIED=()
PIN_STANZAS=()
declare -A REGISTRY_PACKAGES
 
today_epoch="$(date -u -d "$(date -u +%Y-%m-%d)" +%s)"
 
for i in $(seq 0 $((registry_count - 1))); do
    pkg="$(jq -r ".holds[${i}].package" "${REGISTRY_PATH}")"
    reason="$(jq -r ".holds[${i}].reason" "${REGISTRY_PATH}")"
    owner="$(jq -r ".holds[${i}].owner" "${REGISTRY_PATH}")"
    review_date="$(jq -r ".holds[${i}].review_date" "${REGISTRY_PATH}")"
    pin_version="$(jq -r ".holds[${i}].pin_version" "${REGISTRY_PATH}")"
 
    REGISTRY_PACKAGES["${pkg}"]=1
 
    hold_ok="true"
    if apt-mark hold "${pkg}" >/dev/null 2>&1; then
        printf '  %-24s hold + pin %-28s OK\n' "${pkg}" "${pin_version}"
    else
        printf '  %-24s hold + pin %-28s FAILED\n' "${pkg}" "${pin_version}"
        hold_ok="false"
    fi
 
    review_epoch="$(date -u -d "${review_date}" +%s 2>/dev/null || echo "")"
    if [[ -n "${review_epoch}" ]]; then
        days_to_review=$(( (review_epoch - today_epoch) / 86400 ))
    else
        days_to_review="null"
    fi
 
    APPLIED+=("$(jq -n --arg pkg "${pkg}" --arg reason "${reason}" --arg owner "${owner}" \
        --arg review_date "${review_date}" --arg pin_version "${pin_version}" \
        --argjson days "${days_to_review}" --argjson ok "${hold_ok}" \
        '{package: $pkg, reason: $reason, owner: $owner, review_date: $review_date, pin_version: $pin_version, days_to_review: $days, hold_applied: $ok}')")
 
    PIN_STANZAS+=("Package: ${pkg}"$'\n'"Pin: version ${pin_version}"$'\n'"Pin-Priority: ${PIN_PRIORITY}")
done
 
# ---------------------------------------------------------------------------
# Write the pin fragment fresh - this script is the only writer, so the
# file is fully regenerated every run rather than patched incrementally.
# ---------------------------------------------------------------------------
pin_tmp="$(mktemp)"
{
    echo "// Managed by 10-version_hold.sh (MedDefense Health Systems) - do not"
    echo "// hand-edit; this file is regenerated fresh from hold_registry.json"
    echo "// on every run. Source of truth: hold_registry.json."
    echo ""
    for stanza in "${PIN_STANZAS[@]}"; do
        echo "${stanza}"
        echo ""
    done
} > "${pin_tmp}"
mv "${pin_tmp}" "${PIN_FRAGMENT_PATH}"
chmod 644 "${PIN_FRAGMENT_PATH}"
 
# ---------------------------------------------------------------------------
# 3. Convergence: release any current hold not present in the registry.
# ---------------------------------------------------------------------------
echo "Releasing holds no longer in registry:"
 
RELEASED=()
for held_pkg in "${CURRENT_HOLDS[@]}"; do
    [[ -z "${held_pkg}" ]] && continue
    if [[ -z "${REGISTRY_PACKAGES[${held_pkg}]:-}" ]]; then
        if apt-mark unhold "${held_pkg}" >/dev/null 2>&1; then
            printf '  %-24s released\n' "${held_pkg}"
            RELEASED+=("$(jq -n --arg pkg "${held_pkg}" '{package: $pkg, released: true}')")
        else
            printf '  %-24s FAILED to release\n' "${held_pkg}"
            RELEASED+=("$(jq -n --arg pkg "${held_pkg}" '{package: $pkg, released: false}')")
        fi
    fi
done
if [[ "${#RELEASED[@]}" -eq 0 ]]; then
    echo "  (none)"
fi
 
# ---------------------------------------------------------------------------
# 4/5. Overdue reviews + report
# ---------------------------------------------------------------------------
OVERDUE=()
for entry in "${APPLIED[@]}"; do
    days="$(jq -r '.days_to_review' <<< "${entry}")"
    if [[ "${days}" != "null" && "${days}" -lt 0 ]]; then
        OVERDUE+=("${entry}")
    fi
done
 
echo "Overdue reviews: ${#OVERDUE[@]}"
 
APPLIED_JSON="[$(IFS=,; echo "${APPLIED[*]:-}")]"
RELEASED_JSON="[$(IFS=,; echo "${RELEASED[*]:-}")]"
OVERDUE_JSON="[$(IFS=,; echo "${OVERDUE[*]:-}")]"
 
jq -n \
    --argjson applied "${APPLIED_JSON}" \
    --argjson released "${RELEASED_JSON}" \
    --argjson overdue "${OVERDUE_JSON}" \
    --argjson total_held "${registry_count}" \
    '{applied: $applied, released: $released, overdue_reviews: $overdue, total_held: $total_held}' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
exit 0
