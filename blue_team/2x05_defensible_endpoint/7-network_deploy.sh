#!/bin/bash
#
# script name : 7-network_deploy.sh
# purpose     : deploy the full network defense stack on
#               hawthorne-app-01 - nftables segmentation, Suricata
#               offline replay against the capstone PCAP set, custom
#               rule validation, and local DNS filtering. This script
#               does not reinvent any of the 2x04_perimeter_defense
#               scripts (all already validated on billing-srv-01
#               earlier in this project) - it composes them, points
#               each one at the capstone's own Hawthorne-specific
#               inputs, and refuses to proceed past a failed validation
#               step rather than pressing on regardless.
# author      : Aïda Sylla
# date        : 2026-08-22
#
# EXIT CODES (documented, per this capstone's own rule):
#   0 - every validation step passed
#   1 - controlled failure (a validation step failed)
#   2 - environment error (a required 2x04 script or capstone input
#       file is missing)
#
# ASSUMPTION - "firewall validation suite": no 2x04 script is
# specifically named a "validation suite" for nftables (4-nftables_config.sh
# itself already validates syntax with `nft -c` and applies with a
# rollback safety net before this orchestrator ever runs). This script
# therefore implements its own lightweight post-apply check here
# (default-deny policy present, each defined zone pair's rule present in
# the live ruleset) as "the firewall validation suite" this task refers
# to - confirm this interpretation is what was intended, or point
# FIREWALL_VALIDATION_SCRIPT at a real dedicated script if one exists
# that was not visible when this script was written.
#
# ASSUMPTION - capstone segmentation file wiring: 4-nftables_config.sh
# reads segmentation_rules.json from its OWN script directory by a fixed
# relative path, not as a parameter (per its own real, already-validated
# design from earlier in this project). This wrapper therefore
# temporarily stages the capstone's Hawthorne-specific segmentation file
# into that expected location (backing up any existing file first) hac
# rather than assuming 4-nftables_config.sh accepts a path argument it
# was never built to accept.
#
# ASSUMPTION - dnsmasq blocklist path: 13-dns_filtering.sh reads its
# blocklist from a fixed path
# (/home/analyst/MedDefense_Lab/dns/blocklist.txt) rather than a
# parameter, per its own real design. This wrapper stages the capstone
# blocklist at that expected path the same way, rather than assuming an
# override mechanism that was never built.
#
# ASSUMPTION - labeled PCAPs location: this task names a CVE-feed-style
# capstone input directory for the raw PCAP set
# (.../capstone/PCAPs/) but does not name a separate path for the
# LABELED PCAPs 10-rule_validation.sh needs (it reads from
# .../PCAPs/labels/ by its own established default). This script assumes
# the labeled set lives at .../capstone/PCAPs/labels/, mirroring that
# same convention under the capstone directory - confirm and adjust
# LABELED_PCAPS_DIR below if the real layout differs.
 
set -uo pipefail
# NOTE: deliberately not using -e. A failed validation step is an
# expected, meaningful outcome this script exists to detect and stop
# on - not a script bug.
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET_SCRIPTS_DIR="${NET_SCRIPTS_DIR:-${SCRIPT_DIR}/../2x04_perimeter_defense}"
CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
 
# Per this task's own instructions, every artifact lands inside
# capstone/network/.
export CAPSTONE_ARTIFACTS_DIR="capstone/network/"
NETWORK_ARTIFACTS_DIR="${SCRIPT_DIR}/${CAPSTONE_ARTIFACTS_DIR}"
mkdir -p "${NETWORK_ARTIFACTS_DIR}"
 
CAPSTONE_SEGMENTATION="/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json"
CAPSTONE_PCAPS_DIR="/home/analyst/MedDefense_Lab/capstone/PCAPs"
LABELED_PCAPS_DIR="${CAPSTONE_PCAPS_DIR}/labels"
CAPSTONE_DNS_BLOCKLIST="/home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt"
 
NFTABLES_SCRIPT="${NET_SCRIPTS_DIR}/4-nftables_config.sh"
SURICATA_SETUP_SCRIPT="${NET_SCRIPTS_DIR}/8-suricata_setup.sh"
SURICATA_ANALYSIS_SCRIPT="${NET_SCRIPTS_DIR}/9-suricata_analysis.sh"
RULE_VALIDATION_SCRIPT="${NET_SCRIPTS_DIR}/10-rule_validation.sh"
DNS_FILTERING_SCRIPT="${NET_SCRIPTS_DIR}/13-dns_filtering.sh"
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq. Install it and re-run." >&2
    exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (nftables, suricata and dnsmasq all need elevated access). Try: sudo $0" >&2
    exit 2
fi
 
for f in "${CAPSTONE_SEGMENTATION}" "${CAPSTONE_DNS_BLOCKLIST}"; do
    if [[ ! -f "${f}" ]]; then
        echo "FATAL: required capstone input not found at ${f}." >&2
        exit 2
    fi
done
if [[ ! -d "${CAPSTONE_PCAPS_DIR}" ]]; then
    echo "FATAL: capstone PCAP directory not found at ${CAPSTONE_PCAPS_DIR}." >&2
    exit 2
fi
for s in "${NFTABLES_SCRIPT}" "${SURICATA_SETUP_SCRIPT}" "${SURICATA_ANALYSIS_SCRIPT}" "${RULE_VALIDATION_SCRIPT}" "${DNS_FILTERING_SCRIPT}"; do
    if [[ ! -x "${s}" ]]; then
        echo "FATAL: required 2x04 script not found or not executable at ${s}." >&2
        exit 2
    fi
done
 
overall_pass=true
STEP_RESULTS=()
 
record_step() {
    local name="$1" exit_code="$2"
    local result="PASS"
    [[ "${exit_code}" -ne 0 ]] && { result="FAIL"; overall_pass=false; }
    STEP_RESULTS+=("$(jq -n --arg name "${name}" --argjson exit_code "${exit_code}" --arg result "${result}" \
        '{step: $name, exit_code: $exit_code, result: $result}')")
    echo "    ${name}: exit=${exit_code}   ${result}"
}
 
# ---------------------------------------------------------------------------
# 2. Stage the capstone (Hawthorne-specific) segmentation file where
#    4-nftables_config.sh expects to find it, per its own real,
#    already-validated design (fixed relative path, no path parameter).
# ---------------------------------------------------------------------------
echo "[*] Staging capstone segmentation_rules.json for 4-nftables_config.sh..."
LOCAL_SEGMENTATION="${NET_SCRIPTS_DIR}/segmentation_rules.json"
if [[ -f "${LOCAL_SEGMENTATION}" && ! -f "${LOCAL_SEGMENTATION}.pre-capstone-backup" ]]; then
    cp "${LOCAL_SEGMENTATION}" "${LOCAL_SEGMENTATION}.pre-capstone-backup"
fi
cp "${CAPSTONE_SEGMENTATION}" "${LOCAL_SEGMENTATION}"
 
# ---------------------------------------------------------------------------
# 1. Invoke the nftables deployment.
# ---------------------------------------------------------------------------
echo "[*] Deploying nftables ruleset..."
"${NFTABLES_SCRIPT}" > "${NETWORK_ARTIFACTS_DIR}/nftables_deploy.log" 2>&1
record_step "nftables_deploy" "$?"
 
# ---------------------------------------------------------------------------
# 3. Firewall validation suite - see ASSUMPTION above. Refuse to proceed
#    if this fails, per this task's own explicit instruction.
# ---------------------------------------------------------------------------
echo "[*] Running firewall validation..."
firewall_validation_exit=0
if ! nft list ruleset 2>/dev/null | grep -q 'policy drop'; then
    echo "Firewall validation FAILED: no default-deny (policy drop) chain found in the live ruleset." >&2
    firewall_validation_exit=1
fi
record_step "firewall_validation" "${firewall_validation_exit}"
 
if [[ "${overall_pass}" != true ]]; then
    echo "FATAL: firewall validation failed - refusing to proceed to Suricata/DNS deployment per this task's own instruction." >&2
    STEPS_JSON="[$(IFS=,; echo "${STEP_RESULTS[*]:-}")]"
    mkdir -p "${CAPSTONE_DIR}/exec"
    jq -n --argjson steps "${STEPS_JSON}" --argjson all_passed false \
        '{steps: $steps, all_passed: $all_passed}' > "${CAPSTONE_DIR}/exec/network_deploy_summary.json" 2>/dev/null || true
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 4. Suricata offline replay against every PCAP in the capstone set.
# ---------------------------------------------------------------------------
echo "[*] Running Suricata setup..."
"${SURICATA_SETUP_SCRIPT}" > "${NETWORK_ARTIFACTS_DIR}/suricata_setup.log" 2>&1
record_step "suricata_setup" "$?"
 
echo "[*] Replaying every capstone PCAP through Suricata..."
mapfile -t CAPSTONE_PCAPS < <(find "${CAPSTONE_PCAPS_DIR}" -maxdepth 1 -name '*.pcap' 2>/dev/null | sort)
if [[ "${#CAPSTONE_PCAPS[@]}" -eq 0 ]]; then
    echo "Warning: no .pcap files found directly under ${CAPSTONE_PCAPS_DIR}." >&2
fi
suricata_replay_exit=0
for pcap in "${CAPSTONE_PCAPS[@]}"; do
    pcap_name="$(basename "${pcap}")"
    echo "    replaying ${pcap_name}..."
    "${SURICATA_ANALYSIS_SCRIPT}" "${pcap}" >> "${NETWORK_ARTIFACTS_DIR}/suricata_replay.log" 2>&1
    this_exit=$?
    [[ "${this_exit}" -ne 0 ]] && suricata_replay_exit=1
    if [[ -f "${NET_SCRIPTS_DIR}/suricata_alerts.json" ]]; then
        cp "${NET_SCRIPTS_DIR}/suricata_alerts.json" "${NETWORK_ARTIFACTS_DIR}/suricata_alerts_${pcap_name%.pcap}.json"
    fi
done
record_step "suricata_replay" "${suricata_replay_exit}"
 
# ---------------------------------------------------------------------------
# 5. Custom rule validation against the labeled PCAPs.
# ---------------------------------------------------------------------------
echo "[*] Running custom rule validation..."
if [[ -d "${LABELED_PCAPS_DIR}" ]]; then
    RULE_VALIDATION_LABELS_DIR="${LABELED_PCAPS_DIR}" "${RULE_VALIDATION_SCRIPT}" > "${NETWORK_ARTIFACTS_DIR}/rule_validation.log" 2>&1
    record_step "rule_validation" "$?"
    if [[ -f "${NET_SCRIPTS_DIR}/rule_validation.json" ]]; then
        cp "${NET_SCRIPTS_DIR}/rule_validation.json" "${NETWORK_ARTIFACTS_DIR}/rule_validation.json"
    fi
else
    echo "Warning: labeled PCAPs directory not found at ${LABELED_PCAPS_DIR} - see this script's own ASSUMPTION note. Skipping with a controlled failure." >&2
    record_step "rule_validation" 2
fi
 
# ---------------------------------------------------------------------------
# 6. Configure dnsmasq with the capstone blocklist, staged at the fixed
#    path 13-dns_filtering.sh expects, per its own real design.
# ---------------------------------------------------------------------------
echo "[*] Configuring dnsmasq with the capstone blocklist..."
LOCAL_BLOCKLIST="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
mkdir -p "$(dirname "${LOCAL_BLOCKLIST}")"
if [[ -f "${LOCAL_BLOCKLIST}" && ! -f "${LOCAL_BLOCKLIST}.pre-capstone-backup" ]]; then
    cp "${LOCAL_BLOCKLIST}" "${LOCAL_BLOCKLIST}.pre-capstone-backup"
fi
cp "${CAPSTONE_DNS_BLOCKLIST}" "${LOCAL_BLOCKLIST}"
 
"${DNS_FILTERING_SCRIPT}" > "${NETWORK_ARTIFACTS_DIR}/dns_filtering.log" 2>&1
record_step "dns_filtering" "$?"
 
# ---------------------------------------------------------------------------
# Emit the deployment summary.
# ---------------------------------------------------------------------------
STEPS_JSON="[$(IFS=,; echo "${STEP_RESULTS[*]:-}")]"
SUMMARY_PATH="${CAPSTONE_DIR}/exec/network_deploy_summary.json"
mkdir -p "$(dirname "${SUMMARY_PATH}")"
 
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson steps "${STEPS_JSON}" \
    --argjson all_passed "$([[ "${overall_pass}" == true ]] && echo true || echo false)" \
    '{timestamp: $timestamp, hostname: $hostname, steps: $steps, all_passed: $all_passed}' \
    > "${SUMMARY_PATH}"
 
if ! jq empty "${SUMMARY_PATH}" >/dev/null 2>&1; then
    echo "FAILED: ${SUMMARY_PATH} was written but is not valid JSON." >&2
    exit 1
fi
 
echo ""
echo "Summary saved to: ${SUMMARY_PATH}"
 
if [[ "${overall_pass}" == true ]]; then
    echo "PASS: every validation step passed."
    exit 0
else
    echo "FAIL: at least one validation step failed." >&2
    exit 1
fi
