#!/bin/bash
#
# script name : 3-patch_plan.sh
# purpose     : cross-reference vulnerability_inventory.json (Task 0) with
#               service_dependency_map.json (Task 1) to produce a
#               deterministic, ordered patch plan: a priority score per
#               vulnerable package (CVSS, CISA KEV, service criticality,
#               exposure), the services each patch will disturb, whether a
#               restart or a full reboot is required, and the rollback
#               target version - classified into emergency / urgent /
#               scheduled buckets. Emits patch_plan.json.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -euo pipefail
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULN_PATH="${SCRIPT_DIR}/vulnerability_inventory.json"
SVC_MAP_PATH="${SCRIPT_DIR}/service_dependency_map.json"
OUTPUT_PATH="${SCRIPT_DIR}/patch_plan.json"
 
# ---------------------------------------------------------------------------
# Weights (constants). Score formula:
#   cvss_weight * max_cvss
#   + kev_weight * in_cisa_kev (0/1)
#   + criticality_weight * max(criticality of linked services, ordinal)
#   + exposure_weight * exposure_rank
#
# criticality ordinal: critical=4, high=3, medium=2, low=1, untied=0.
#
# exposure_rank: NOT defined by the task's own data model - this script
# only reads vulnerability_inventory.json and service_dependency_map.json
# (no listening-socket data is available here, that lives in
# pre_patch_state.json from Task 2, which is not an input to this task).
# exposure_rank is therefore derived as the number of DISTINCT active
# services a package affects, capped at 3: a package disturbing more
# running services has a wider operational blast radius. This is a
# reasonable engineering interpretation given the available inputs, not an
# external standard - document/adjust it if your program expects a
# different exposure signal (e.g. network-facing vs not).
# ---------------------------------------------------------------------------
CVSS_WEIGHT=0.6
KEV_WEIGHT=2.0
CRITICALITY_WEIGHT=0.5
EXPOSURE_WEIGHT=0.3
 
EMERGENCY_THRESHOLD=7
URGENT_THRESHOLD=4
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to join the two input files. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
for f in "${VULN_PATH}" "${SVC_MAP_PATH}"; do
    if [[ ! -f "${f}" ]]; then
        echo "Required input file not found: ${f}. Run 0-vuln_inventory.sh and 1-service_deps.sh first." >&2
        exit 1
    fi
    if ! jq empty "${f}" >/dev/null 2>&1; then
        echo "File is not valid JSON: ${f}" >&2
        exit 1
    fi
done
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
criticality_ordinal() {
    case "$1" in
        critical) echo 4 ;;
        high)     echo 3 ;;
        medium)   echo 2 ;;
        low)      echo 1 ;;
        *)        echo 0 ;;
    esac
}
 
is_kernel_or_systemd() {
    local pkg="$1"
    case "${pkg}" in
        linux-image*|linux-modules*|linux-generic*|linux-headers*) return 0 ;;
        systemd) return 0 ;;
        *) return 1 ;;
    esac
}
 
echo "[*] Building patch plan from vulnerability_inventory.json and service_dependency_map.json..."
 
vuln_count="$(jq '.packages | length' "${VULN_PATH}")"
 
PLAN_ENTRIES=()
emergency_count=0
urgent_count=0
scheduled_count=0
kernel_present="false"
 
for i in $(seq 0 $((vuln_count - 1))); do
    pkg="$(jq -r ".packages[${i}].package" "${VULN_PATH}")"
    installed_version="$(jq -r ".packages[${i}].installed_version" "${VULN_PATH}")"
    max_cvss="$(jq -r ".packages[${i}].max_cvss" "${VULN_PATH}")"
    [[ "${max_cvss}" == "null" ]] && max_cvss="0"
    in_kev="$(jq -r ".packages[${i}].in_cisa_kev" "${VULN_PATH}")"
    kev_numeric=0
    [[ "${in_kev}" == "true" ]] && kev_numeric=1
 
    # ------------------------------------------------------------------
    # Affected services: every service whose owning_package matches this
    # package, or whose linked_packages array contains it. Kernel/systemd
    # packages use the special "(kernel-wide)" marker instead, since no
    # userspace service ever lists a kernel package as a linked dependency.
    # ------------------------------------------------------------------
    if is_kernel_or_systemd "${pkg}"; then
        affected_services_json='["(kernel-wide)"]'
        affected_count=0
        max_criticality_ordinal=4
        requires_reboot="true"
        kernel_present="true"
    else
        mapfile -t affected < <(jq -r --arg p "${pkg}" '
            .services[] | select(.owning_package == $p or (.linked_packages | index($p) != null)) | .service
        ' "${SVC_MAP_PATH}")
        affected_count="${#affected[@]}"
 
        parts=()
        for s in "${affected[@]}"; do
            [[ -z "${s}" ]] && continue
            parts+=("\"$(json_escape "${s}")\"")
        done
        affected_services_json="[$(IFS=,; echo "${parts[*]:-}")]"
 
        max_criticality_ordinal=0
        for s in "${affected[@]}"; do
            [[ -z "${s}" ]] && continue
            crit="$(jq -r --arg svc "${s}" '.services[] | select(.service == $svc) | .criticality' "${SVC_MAP_PATH}" | head -1)"
            ord="$(criticality_ordinal "${crit}")"
            [[ "${ord}" -gt "${max_criticality_ordinal}" ]] && max_criticality_ordinal="${ord}"
        done
        requires_reboot="false"
    fi
 
    requires_restart="false"
    [[ "${affected_count}" -gt 0 || "${affected_services_json}" == '["(kernel-wide)"]' ]] && requires_restart="true"
 
    exposure_rank="${affected_count}"
    [[ "${exposure_rank}" -gt 3 ]] && exposure_rank=3
 
    score="$(awk -v cvss="${max_cvss}" -v kev="${kev_numeric}" -v crit="${max_criticality_ordinal}" -v expo="${exposure_rank}" \
        -v wc="${CVSS_WEIGHT}" -v wk="${KEV_WEIGHT}" -v wcr="${CRITICALITY_WEIGHT}" -v we="${EXPOSURE_WEIGHT}" \
        'BEGIN { printf "%.2f", (wc*cvss) + (wk*kev) + (wcr*crit) + (we*expo) }')"
 
    if awk -v s="${score}" -v t="${EMERGENCY_THRESHOLD}" 'BEGIN{exit !(s>=t)}'; then
        bucket="emergency"
        emergency_count=$((emergency_count + 1))
    elif awk -v s="${score}" -v t="${URGENT_THRESHOLD}" 'BEGIN{exit !(s>=t)}'; then
        bucket="urgent"
        urgent_count=$((urgent_count + 1))
    else
        bucket="scheduled"
        scheduled_count=$((scheduled_count + 1))
    fi
 
    # Sort key encodes the score INVERTED (a large constant minus the
    # score) so that a single ASCENDING sort_by, with no separate
    # reverse(), already yields highest-score-first while still breaking
    # ties by package name in natural ascending order. A plain
    # score-then-reverse() approach (tried first, caught by testing) also
    # flips the tie-break order, silently turning "aaa-pkg before zzz-pkg"
    # into the opposite for any two packages that land on the same score.
    inverted_score="$(awk -v s="${score}" 'BEGIN { printf "%08.2f", 99999.99 - s }')"
    sort_key="$(printf '%s_%s' "${inverted_score}" "${pkg}")"
 
    entry=$(printf '{"sort_key":"%s","package":"%s","installed_version":"%s","score":%s,"bucket":"%s","affected_services":%s,"requires_restart":%s,"requires_reboot":%s,"rollback_target_version":"%s"}' \
        "$(json_escape "${sort_key}")" "$(json_escape "${pkg}")" "$(json_escape "${installed_version}")" \
        "${score}" "${bucket}" "${affected_services_json}" "${requires_restart}" "${requires_reboot}" "$(json_escape "${installed_version}")")
 
    PLAN_ENTRIES+=("${entry}")
done
 
# ---------------------------------------------------------------------------
# Deterministic ranking: sort_key already encodes an inverted score, so a
# plain ASCENDING sort_by yields highest-score-first with package name
# ascending as the natural tie-breaker - no separate reverse() needed (see
# the note where sort_key is built for why reverse() would silently break
# tie-break ordering).
# ---------------------------------------------------------------------------
echo "[*] Ranking ${#PLAN_ENTRIES[@]} vulnerable packages..."
 
SORTED_ENTRIES_JSON="$(printf '%s\n' "${PLAN_ENTRIES[@]}" | jq -s 'sort_by(.sort_key)')"
 
FINAL_PLAN="$(jq '[ to_entries[] | {
    rank: (.key + 1),
    package: .value.package,
    installed_version: .value.installed_version,
    score: .value.score,
    bucket: .value.bucket,
    affected_services: .value.affected_services,
    requires_restart: .value.requires_restart,
    requires_reboot: .value.requires_reboot,
    rollback_target_version: .value.rollback_target_version
} ]' <<< "${SORTED_ENTRIES_JSON}")"
 
echo "Emergency: ${emergency_count}   Urgent: ${urgent_count}   Scheduled: ${scheduled_count}"
if [[ "${kernel_present}" == "true" ]]; then
    echo "Reboot required by plan: yes (kernel update present)"
else
    echo "Reboot required by plan: no"
fi
 
# ---------------------------------------------------------------------------
# Write patch_plan.json
# ---------------------------------------------------------------------------
jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson cvss_weight "${CVSS_WEIGHT}" \
    --argjson kev_weight "${KEV_WEIGHT}" \
    --argjson criticality_weight "${CRITICALITY_WEIGHT}" \
    --argjson exposure_weight "${EXPOSURE_WEIGHT}" \
    --argjson plan "${FINAL_PLAN}" \
    --argjson emergency "${emergency_count}" \
    --argjson urgent "${urgent_count}" \
    --argjson scheduled "${scheduled_count}" \
    --argjson kernel_present "${kernel_present}" \
    '{
        generated_at: $generated_at,
        weights: { cvss: $cvss_weight, kev: $kev_weight, criticality: $criticality_weight, exposure: $exposure_weight },
        plan: $plan,
        summary: { emergency: $emergency, urgent: $urgent, scheduled: $scheduled, reboot_required: $kernel_present, total: ($emergency + $urgent + $scheduled) }
    }' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
