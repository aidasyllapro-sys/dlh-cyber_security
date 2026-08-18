#!/bin/bash
#
# script name : 9-suricata_analysis.sh
# purpose     : replay a PCAP through Suricata (using Task 8's
#               suricata.yaml) and turn the resulting eve.json into a
#               classified, ranked alert report - grouping every alert by
#               signature, source, destination and severity, and tagging
#               each signature with a threat category from a
#               project-supplied signature_categories.json map, so a
#               Tier 1 analyst can triage dozens of raw alerts at a
#               glance instead of reading them one by one. This script
#               reads and aggregates the ruleset's own verdicts - it
#               never writes detection logic of its own.
# author      : Aïda Sylla
# date        : 2026-08-17
 
set -uo pipefail
# NOTE: deliberately not using -e. Zero alerts, an unclassified signature
# (falling back to "other"), or a missing signature_categories.json are
# all expected, meaningful outcomes this script exists to report - not
# script bugs.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (suricata needs to read the PCAP and write to the log directory). Try: sudo $0" >&2
    exit 1
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
if ! command -v suricata >/dev/null 2>&1; then
    echo "suricata not found. Run 8-suricata_setup.sh first." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${SCRIPT_DIR}/suricata.yaml"
CATEGORIES_PATH="${SCRIPT_DIR}/signature_categories.json"
OUTPUT_PATH="${SCRIPT_DIR}/suricata_alerts.json"
TMP_LOG_DIR="$(mktemp -d /tmp/suricata-analysis.XXXXXX)"
 
# 1. Accept a PCAP path as argument, default to the project's mixed
#    traffic capture.
PCAP_PATH="${1:-/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap}"
 
if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "suricata.yaml not found at ${CONFIG_PATH}. Run 8-suricata_setup.sh first." >&2
    exit 1
fi
if [[ ! -f "${PCAP_PATH}" ]]; then
    echo "PCAP not found at ${PCAP_PATH}." >&2
    exit 1
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
# ---------------------------------------------------------------------------
# signature_categories.json is a project-supplied fixture this task
# references but does not define a schema for. Assumed schema (documented
# here, adjust if the project supplies a different one):
#   { "<signature_id>": "<category>", ... } - keyed by the numeric
#   Suricata signature ID (alert.signature_id) as a string, since SIDs
#   are stable and unambiguous, unlike free-text signature names which
#   can vary slightly by ruleset version. Category values expected:
#   reconnaissance, exploit, lateral_movement, exfiltration, malware_c2,
#   policy_violation, other. Any signature ID not present in the map (or
#   the map itself missing) falls back to "other" - never left unlabeled.
# ---------------------------------------------------------------------------
HAVE_CATEGORIES=false
if [[ -f "${CATEGORIES_PATH}" ]] && jq empty "${CATEGORIES_PATH}" >/dev/null 2>&1; then
    HAVE_CATEGORIES=true
else
    echo "Warning: signature_categories.json not found or invalid - every alert's category will default to 'other'." >&2
fi
 
# ---------------------------------------------------------------------------
# 2. Replay the PCAP through Suricata and wait for completion.
#    Per this task's own instructions: suricata -c ./suricata.yaml -r
#    <pcap> -l <tmpdir> - CONFIG_PATH below resolves to that same
#    ./suricata.yaml (Task 8's rendered config, in this script's own
#    directory), just referenced via an absolute path built from
#    SCRIPT_DIR rather than the literal relative string, so the command
#    works correctly regardless of the caller's current working
#    directory.
# ---------------------------------------------------------------------------
echo "[*] Replaying ${PCAP_PATH} through Suricata..."
started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
 
suricata -c "${CONFIG_PATH}" -r "${PCAP_PATH}" -l "${TMP_LOG_DIR}/" > /tmp/suricata_analysis_run.log 2>&1
suricata_exit=$?
 
finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "    suricata exit: ${suricata_exit}"
 
EVE_PATH="${TMP_LOG_DIR}/eve.json"
if [[ ! -f "${EVE_PATH}" ]]; then
    echo "FAILED: eve.json was not produced at ${EVE_PATH}. See /tmp/suricata_analysis_run.log" >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 3/4. Parse eve.json, keep only alert records, extract the required
#      fields per alert.
# ---------------------------------------------------------------------------
echo "[*] Parsing eve.json..."
 
ALERTS_TSV="$(mktemp)"
jq -r 'select(.event_type == "alert") | [
    (.timestamp // ""),
    (.src_ip // ""),
    (.src_port // 0 | tostring),
    (.dest_ip // ""),
    (.dest_port // 0 | tostring),
    (.proto // ""),
    (.alert.signature // ""),
    (.alert.signature_id // 0 | tostring),
    (.alert.category // ""),
    (.alert.severity // 0 | tostring)
] | @tsv' "${EVE_PATH}" > "${ALERTS_TSV}" 2>/dev/null
 
total_alerts="$(wc -l < "${ALERTS_TSV}" | tr -d ' ')"
echo "    ${total_alerts} alert records found."
 
# ---------------------------------------------------------------------------
# 6. Load category map (signature_id -> category).
# ---------------------------------------------------------------------------
lookup_category() {
    local sid="$1"
    if [[ "${HAVE_CATEGORIES}" != true ]]; then
        echo "other"; return
    fi
    local cat
    cat="$(jq -r --arg s "${sid}" '.[$s] // "other"' "${CATEGORIES_PATH}" 2>/dev/null || echo "other")"
    [[ -z "${cat}" || "${cat}" == "null" ]] && cat="other"
    echo "${cat}"
}
 
# ---------------------------------------------------------------------------
# 5/6. Build the alerts array, and accumulate aggregates as we go.
# ---------------------------------------------------------------------------
echo "[*] Classifying and aggregating..."
 
ALERT_ENTRIES=()
declare -A SIG_COUNT
declare -A SRC_COUNT
declare -A DST_COUNT
declare -A SEV_COUNT
declare -A CAT_COUNT
declare -A SEEN_SIGS
 
while IFS=$'\t' read -r ts src_ip src_port dst_ip dst_port proto sig sid category severity; do
    [[ -z "${ts}" ]] && continue
 
    # NOTE: found the hard way on billing-srv-01 against a real alert
    # with no priority/classtype set (so eve.json's alert.severity was
    # entirely absent, not just zero) - relying only on jq's `// 0`
    # fallback during TSV extraction wasn't enough to guarantee a
    # non-empty value survives into these bash variables, and using an
    # empty string as an associative array subscript triggers "bad array
    # subscript". Defaulting every field explicitly here, right before
    # first use, closes that gap regardless of what upstream jq produced.
    src_ip="${src_ip:-unknown}"
    dst_ip="${dst_ip:-unknown}"
    sig="${sig:-unknown}"
    sid="${sid:-0}"
    category="${category:-unknown}"
    severity="${severity:-0}"
 
    threat_category="$(lookup_category "${sid}")"
 
    SIG_COUNT["${sig}"]=$(( ${SIG_COUNT["${sig}"]:-0} + 1 ))
    SRC_COUNT["${src_ip}"]=$(( ${SRC_COUNT["${src_ip}"]:-0} + 1 ))
    DST_COUNT["${dst_ip}"]=$(( ${DST_COUNT["${dst_ip}"]:-0} + 1 ))
    SEV_COUNT["${severity}"]=$(( ${SEV_COUNT["${severity}"]:-0} + 1 ))
    CAT_COUNT["${threat_category}"]=$(( ${CAT_COUNT["${threat_category}"]:-0} + 1 ))
    SEEN_SIGS["${sig}"]=1
 
    ALERT_ENTRIES+=("$(jq -n \
        --arg ts "${ts}" --arg src_ip "${src_ip}" --argjson src_port "${src_port:-0}" \
        --arg dst_ip "${dst_ip}" --argjson dst_port "${dst_port:-0}" --arg proto "${proto}" \
        --arg sig "${sig}" --argjson sid "${sid:-0}" --arg category "${category}" \
        --argjson severity "${severity:-0}" --arg threat_category "${threat_category}" \
        '{timestamp: $ts, src_ip: $src_ip, src_port: $src_port, dst_ip: $dst_ip, dst_port: $dst_port,
          proto: $proto, signature: $sig, signature_id: $sid, category: $category,
          severity: $severity, threat_category: $threat_category}')")
done < "${ALERTS_TSV}"
 
rm -f "${ALERTS_TSV}"
 
# NOTE: found the hard way on billing-srv-01's real bash - referencing
# ${#assoc_array[@]} on an associative array that was `declare -A`'d but
# never had a single element assigned (e.g. when there are zero alerts)
# triggers "unbound variable" under `set -u` on some bash versions, even
# though the array itself is legitimately empty rather than truly unset.
# Disabling nounset around this specific read avoids depending on that
# version-specific quirk.
set +u
unique_signatures="${#SEEN_SIGS[@]}"
set -u
echo "    ${unique_signatures} unique signatures."
 
# ---------------------------------------------------------------------------
# Build the summary JSON blocks.
# ---------------------------------------------------------------------------
build_count_json() {
    # Reads an associative-array-name and prints a sorted (desc) JSON
    # array of {key, count}, via a temp file since bash can't pass
    # associative arrays by reference cleanly across all versions.
    local -n arr_ref="$1"
    local key_field="$2"
    local entries=()
    # See the note above build_count_json's caller: guarding against the
    # same real "unbound variable on an empty associative array" bash
    # quirk confirmed on billing-srv-01, this time for both the key
    # iteration and the entries-count check.
    set +u
    for k in "${!arr_ref[@]}"; do
        entries+=("$(jq -n --arg k "${k}" --argjson c "${arr_ref[${k}]}" --arg kf "${key_field}" \
            '{($kf): $k, count: $c}')")
    done
    local entry_count="${#entries[@]}"
    set -u
    if [[ "${entry_count}" -eq 0 ]]; then
        echo "[]"
        return
    fi
    printf '%s\n' "${entries[@]}" | jq -s 'sort_by(-.count)'
}
 
by_signature_json="$(build_count_json SIG_COUNT signature)"
top_sources_json="$(build_count_json SRC_COUNT ip | jq -c '.[0:10]')"
top_destinations_json="$(build_count_json DST_COUNT ip | jq -c '.[0:10]')"
severity_distribution_json="$(build_count_json SEV_COUNT severity)"
by_category_json="$(build_count_json CAT_COUNT category)"
 
ALERTS_JSON="[$(IFS=,; echo "${ALERT_ENTRIES[*]:-}")]"
 
# ---------------------------------------------------------------------------
# 7. Emit suricata_alerts.json
# ---------------------------------------------------------------------------
jq -n \
    --arg pcap "${PCAP_PATH}" \
    --arg started_at "${started_at}" \
    --arg finished_at "${finished_at}" \
    --argjson total_alerts "${total_alerts}" \
    --argjson unique_signatures "${unique_signatures}" \
    --argjson severity_distribution "${severity_distribution_json}" \
    --argjson by_category "${by_category_json}" \
    --argjson by_signature "${by_signature_json}" \
    --argjson top_sources "${top_sources_json}" \
    --argjson top_destinations "${top_destinations_json}" \
    --argjson alerts "${ALERTS_JSON}" \
    '{
        pcap: $pcap,
        started_at: $started_at,
        finished_at: $finished_at,
        total_alerts: $total_alerts,
        unique_signatures: $unique_signatures,
        severity_distribution: $severity_distribution,
        by_category: $by_category,
        by_signature: $by_signature,
        top_sources: $top_sources,
        top_destinations: $top_destinations,
        alerts: $alerts
    }' > "${OUTPUT_PATH}"
 
echo "Total alerts: ${total_alerts}   Unique signatures: ${unique_signatures}"
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
 
rm -rf "${TMP_LOG_DIR}"
exit 0
