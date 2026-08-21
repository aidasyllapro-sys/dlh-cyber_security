#!/bin/bash
#
# script name : 10-rule_validation.sh
# purpose     : prove every custom rule in meddefense.rules actually
#               fires against its target labeled PCAP - loading ONLY
#               meddefense.rules (isolated from the community ruleset,
#               so a pass/fail here is unambiguously about this project's
#               own rules), replaying each labeled PCAP through Suricata,
#               and confirming the expected signature ID appears in the
#               resulting eve.json. A rule that never fires is worse than
#               no rule at all - this script exists to catch exactly
#               that before Tasks 11+ rely on these rules being real.
# author      : Aïda Sylla
# date        : 2026-08-17
 
set -uo pipefail
# NOTE: deliberately not using -e. A rule failing to fire against its
# target PCAP is an expected, meaningful outcome this script exists to
# detect and report clearly - not a script bug. Every command whose
# non-zero exit is normal control flow is handled explicitly.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (suricata needs to read the PCAPs and write to the log directory). Try: sudo $0" >&2
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
RULES_PATH="${SCRIPT_DIR}/meddefense.rules"
CONFIG_PATH="${SCRIPT_DIR}/suricata.yaml"
LABELS_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"
TMP_LOG_DIR="$(mktemp -d /tmp/meddefense-rule-validation.XXXXXX)"
ISOLATED_CONFIG="$(mktemp)"
 
if [[ ! -f "${RULES_PATH}" ]]; then
    echo "meddefense.rules not found at ${RULES_PATH}." >&2
    exit 1
fi
if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "suricata.yaml not found at ${CONFIG_PATH}. Run 8-suricata_setup.sh first." >&2
    exit 1
fi
if [[ ! -d "${LABELS_DIR}" ]]; then
    echo "Labeled PCAP directory not found at ${LABELS_DIR}. Cannot validate without the project-supplied labeled captures." >&2
    exit 1
fi
 
rule_count="$(grep -cE '^(alert|pass|drop|reject)[[:space:]]' "${RULES_PATH}" 2>/dev/null || echo 0)"
echo "[*] Loading meddefense.rules...          ${rule_count} rules"
 
# ---------------------------------------------------------------------------
# Build an isolated copy of suricata.yaml pointing default-rule-path at
# this project directory and rule-files at ONLY meddefense.rules, so a
# match is unambiguously attributable to this rule file, not the
# community ruleset loaded alongside it in Task 8's normal config.
# ---------------------------------------------------------------------------
{
    grep -v '^rule-files:' "${CONFIG_PATH}" | grep -v '^  - .*\.rules$'
    echo "rule-files:"
    echo "  - $(basename "${RULES_PATH}")"
} > "${ISOLATED_CONFIG}.tmp"
 
# The filter above strips the old rule-files block; also override
# default-rule-path to this script's own directory so the bare filename
# above resolves correctly regardless of Task 8's rule directory.
sed "s#^default-rule-path:.*#default-rule-path: ${SCRIPT_DIR}#" "${ISOLATED_CONFIG}.tmp" > "${ISOLATED_CONFIG}"
rm -f "${ISOLATED_CONFIG}.tmp"
 
# ---------------------------------------------------------------------------
# Mapping of expected sid -> {name, target pcap} - this project's own
# naming convention (documented since the task names PCAPs by scenario
# without formally defining the mapping schema itself).
# ---------------------------------------------------------------------------
SID_LIST=(9000001 9000002 9000003 9000004 9000005 9000006)
declare -A SID_NAME=(
    [9000001]="MEDDEV to Internet"
    [9000002]="Guest to SMB"
    [9000003]="Large Outbound From Server"
    [9000004]="DNS Tunneling Long Label"
    [9000005]="Clinical to Unauthorized DB"
    [9000006]="Telnet to MEDDEV"
)
declare -A SID_PCAP=(
    [9000001]="meddev_egress.pcap"
    [9000002]="guest_smb.pcap"
    [9000003]="large_outbound.pcap"
    [9000004]="dns_tunnel.pcap"
    [9000005]="clinical_wrong_db.pcap"
    [9000006]="telnet_meddev.pcap"
)
 
echo "[*] Running validation against labeled PCAPs..."
echo ""
 
passed=0
failed=0
RESULT_ENTRIES=()
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
for sid in "${SID_LIST[@]}"; do
    name="${SID_NAME[${sid}]}"
    pcap_name="${SID_PCAP[${sid}]}"
    pcap_path="${LABELS_DIR}/${pcap_name}"
 
    echo "sid ${sid} ${name}"
    echo "  target: ${pcap_name}"
    echo "  expected: fire"
 
    if [[ ! -f "${pcap_path}" ]]; then
        echo "  observed: PCAP NOT FOUND                FAIL"
        echo ""
        failed=$((failed + 1))
        RESULT_ENTRIES+=("$(jq -n --argjson sid "${sid}" --arg name "${name}" --arg pcap "${pcap_name}" \
            '{sid: $sid, name: $name, pcap: $pcap, expected: "fire", observed_hits: 0, result: "FAIL", reason: "pcap not found"}')")
        continue
    fi
 
    run_log_dir="${TMP_LOG_DIR}/${sid}"
    mkdir -p "${run_log_dir}"
    suricata -c "${ISOLATED_CONFIG}" -r "${pcap_path}" -l "${run_log_dir}/" > "${run_log_dir}/run.log" 2>&1
 
    eve_path="${run_log_dir}/eve.json"
    hit_count=0
    if [[ -f "${eve_path}" ]]; then
        hit_count="$(jq -r --argjson s "${sid}" 'select(.event_type == "alert" and .alert.signature_id == $s)' "${eve_path}" 2>/dev/null | jq -s 'length' 2>/dev/null || echo 0)"
    fi
 
    if [[ "${hit_count}" -gt 0 ]]; then
        echo "  observed: fire (${hit_count} hits)                PASS"
        passed=$((passed + 1))
        RESULT_ENTRIES+=("$(jq -n --argjson sid "${sid}" --arg name "${name}" --arg pcap "${pcap_name}" --argjson hits "${hit_count}" \
            '{sid: $sid, name: $name, pcap: $pcap, expected: "fire", observed_hits: $hits, result: "PASS", reason: null}')")
    else
        echo "  observed: no fire (0 hits)               FAIL"
        failed=$((failed + 1))
        RESULT_ENTRIES+=("$(jq -n --argjson sid "${sid}" --arg name "${name}" --arg pcap "${pcap_name}" \
            '{sid: $sid, name: $name, pcap: $pcap, expected: "fire", observed_hits: 0, result: "FAIL", reason: "rule never fired"}')")
    fi
    echo ""
done
 
echo "Rules:  ${#SID_LIST[@]}"
echo "Passed: ${passed}"
echo "Failed: ${failed}"
 
# ---------------------------------------------------------------------------
# Emit rule_validation.json - this project's own rule that JSON is the
# deliverable format for every validation/tracking task, not just the
# human-readable console summary above.
# ---------------------------------------------------------------------------
RESULTS_JSON="[$(IFS=,; echo "${RESULT_ENTRIES[*]:-}")]"
RULE_VALIDATION_OUTPUT="${SCRIPT_DIR}/rule_validation.json"
 
jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson total_rules "${#SID_LIST[@]}" \
    --argjson passed "${passed}" \
    --argjson failed "${failed}" \
    --argjson results "${RESULTS_JSON}" \
    '{generated_at: $generated_at, total_rules: $total_rules, passed: $passed, failed: $failed, results: $results}' \
    > "${RULE_VALIDATION_OUTPUT}"
 
echo "Report saved to: $(basename "${RULE_VALIDATION_OUTPUT}")"
 
rm -rf "${TMP_LOG_DIR}" "${ISOLATED_CONFIG}"
 
if [[ "${failed}" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
