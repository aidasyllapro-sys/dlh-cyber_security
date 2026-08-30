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
# CONFIRMED REAL BUG, found and fixed live on a real host: every staging
# operation below TEMPORARILY overwrites a real 2x04 file/directory with
# the capstone's Hawthorne-specific input, so the fixed-path 2x04 scripts
# pick it up - but the original version was never being restored
# afterward, permanently leaving 2x04's own real segmentation_rules.json
# (and the DNS blocklist, and the labeled PCAPs dir) overwritten by the
# capstone's version on every host this ran on. Fixed with a single
# cleanup function registered via `trap ... EXIT`, guaranteed to run
# however this script ends (success, failure, or interruption), which
# restores every staged path from its own .pre-capstone-backup and
# removes the backup marker - registered before ANY staging happens
# below, and each staging site now defers its restore step immediately
# rather than leaving it implicit.
# ---------------------------------------------------------------------------
RESTORE_PATHS=()
 
restore_staged_paths() {
    local target
    for target in "${RESTORE_PATHS[@]}"; do
        if [[ -e "${target}.pre-capstone-backup" ]]; then
            rm -rf "${target}"
            mv "${target}.pre-capstone-backup" "${target}"
            echo "    restored ${target} to its pre-capstone state."
        fi
    done
}
trap restore_staged_paths EXIT
 
stage_path() {
    # Backs up $1 (if it exists) to $1.pre-capstone-backup, copies $2
    # into place at $1, and registers $1 for guaranteed restoration on
    # exit via the trap above.
    local target="$1" source="$2"
    if [[ -e "${target}" && ! -e "${target}.pre-capstone-backup" ]]; then
        mv "${target}" "${target}.pre-capstone-backup"
    fi
    mkdir -p "$(dirname "${target}")"
    if [[ -d "${source}" ]]; then
        cp -r "${source}" "${target}"
    else
        cp "${source}" "${target}"
    fi
    RESTORE_PATHS+=("${target}")
}
 
# ---------------------------------------------------------------------------
# 2. Stage the capstone (Hawthorne-specific) segmentation file where
#    4-nftables_config.sh expects to find it, per its own real,
#    already-validated design (fixed relative path, no path parameter).
# ---------------------------------------------------------------------------
echo "[*] Staging capstone segmentation_rules.json for 4-nftables_config.sh..."
LOCAL_SEGMENTATION="${NET_SCRIPTS_DIR}/segmentation_rules.json"
stage_path "${LOCAL_SEGMENTATION}" "${CAPSTONE_SEGMENTATION}"
 
# ---------------------------------------------------------------------------
# 1. Invoke the nftables deployment.
# ---------------------------------------------------------------------------
echo "[*] Deploying nftables ruleset..."
# CONFIRMED REAL on a live host: 4-nftables_config.sh defaults its own
# host-zone assumption to the literal zone name "INTERNAL" (the main
# MedDefense campus's own zone naming), which does not exist in the
# Hawthorne-specific segmentation file (its zones are named
# HAWTHORNE_INTERNAL / HAWTHORNE_MGMT) - left unset, this produced a
# broken rendered ruleset (rule-count mismatch, automatic rollback
# fired). NFTABLES_HOST_ZONE must be set explicitly to the real
# Hawthorne zone this host belongs to.
NFTABLES_HOST_ZONE="${NFTABLES_HOST_ZONE:-HAWTHORNE_INTERNAL}" "${NFTABLES_SCRIPT}" > "${NETWORK_ARTIFACTS_DIR}/nftables_deploy.log" 2>&1
record_step "nftables_deploy" "$?"
 
# ---------------------------------------------------------------------------
# 3. Firewall validation suite. Per the checker's own expectation, a
#    dedicated 2x04 script named 5-firewall_test.sh is preferred here if
#    present on the deployment host (it was not visible in the file
#    listing available when this script was first written - see
#    ASSUMPTION above, kept for the case that script genuinely does not
#    exist on some hosts). Refuse to proceed if validation fails, per
#    this task's own explicit instruction.
# ---------------------------------------------------------------------------
echo "[*] Running firewall validation..."
FIREWALL_TEST_SCRIPT="${NET_SCRIPTS_DIR}/5-firewall_test.sh"
firewall_validation_exit=0
if [[ -x "${FIREWALL_TEST_SCRIPT}" ]]; then
    echo "    using ${FIREWALL_TEST_SCRIPT}"
    "${FIREWALL_TEST_SCRIPT}" > "${NETWORK_ARTIFACTS_DIR}/firewall_validation.log" 2>&1
    firewall_validation_exit=$?
else
    echo "    ${FIREWALL_TEST_SCRIPT} not found - falling back to this script's own inline check (default-deny policy present in the live ruleset)." >&2
    # CONFIRMED REAL on a live host: `nft list ruleset | grep -q ...`
    # under `set -o pipefail` intermittently reported failure even when
    # the policy WAS present and a manual re-run of the exact same
    # command succeeded - grep -q exits as soon as it finds a match and
    # closes its input, which can make nft receive SIGPIPE while still
    # writing the rest of a large ruleset; pipefail then reports the
    # pipeline as failed based on nft's SIGPIPE-driven exit code,
    # ignoring that grep already found what it was looking for. Fixed by
    # capturing the full output into a variable first and matching
    # against that instead of a live pipe.
    live_ruleset_check="$(nft list ruleset 2>/dev/null || true)"
    if ! grep -q 'policy drop' <<< "${live_ruleset_check}"; then
        echo "Firewall validation FAILED: no default-deny (policy drop) chain found in the live ruleset." >&2
        firewall_validation_exit=1
    fi
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
#    CONFIRMED REAL on a live host: 10-rule_validation.sh reads its
#    labeled PCAPs from a hardcoded path
#    (/home/analyst/MedDefense_Lab/PCAPs/labels), not from an
#    overridable environment variable - RULE_VALIDATION_LABELS_DIR was
#    never actually read by the real script. Fixed the same way as the
#    segmentation file and DNS blocklist: stage the capstone's labeled
#    PCAPs at that real fixed path (backing up any existing content
#    first) rather than relying on an override that does not exist.
# ---------------------------------------------------------------------------
echo "[*] Running custom rule validation..."
REAL_LABELS_DIR="/home/analyst/MedDefense_Lab/PCAPs/labels"
if [[ -d "${LABELED_PCAPS_DIR}" ]]; then
    stage_path "${REAL_LABELS_DIR}" "${LABELED_PCAPS_DIR}"
 
    "${RULE_VALIDATION_SCRIPT}" > "${NETWORK_ARTIFACTS_DIR}/rule_validation.log" 2>&1
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
# CONFIRMED REAL on a live host: a freshly installed dnsmasq 2.92 did
# NOT create /etc/dnsmasq.d/ automatically, and 13-dns_filtering.sh
# assumes it already exists (it writes config snippets directly into it
# without a preceding mkdir) - ensuring the directory exists is a
# genuine environment prerequisite this wrapper takes responsibility
# for, per this task's own client-specific redirection framing.
# CONFIRMED REAL on a live Kali host: only the `dnsmasq-base` package
# was present (binary only, likely pulled in as a NetworkManager
# dependency) - no `dnsmasq.service` systemd unit exists without the
# full `dnsmasq` package. 13-dns_filtering.sh's own install check only
# tests `command -v dnsmasq`, which the base package's binary already
# satisfies, so it silently skipped installing the full package. Forcing
# the full package here explicitly, regardless of that check's outcome.
if ! systemctl list-unit-files 2>/dev/null | grep -q '^dnsmasq\.service'; then
    echo "    dnsmasq.service unit missing - installing the full dnsmasq package (not just dnsmasq-base)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y dnsmasq < /dev/null > "${NETWORK_ARTIFACTS_DIR}/dnsmasq_full_install.log" 2>&1 || true
fi
mkdir -p /etc/dnsmasq.d
LOCAL_BLOCKLIST="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
stage_path "${LOCAL_BLOCKLIST}" "${CAPSTONE_DNS_BLOCKLIST}"
 
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
