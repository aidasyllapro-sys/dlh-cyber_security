#!/bin/bash
#
# script name : 8-suricata_setup.sh
# purpose     : prepare Suricata for offline PCAP replay on this hardened
#               endpoint - install the binary and jq idempotently, copy
#               the project-supplied ruleset into the standard rule
#               directory, render a minimal suricata.yaml configured for
#               replay mode (pcap-file enabled, no live interface), run a
#               config-only syntax check, then a real smoke-test replay
#               against a small sample PCAP to confirm the whole chain -
#               install, rules, config - actually produces at least one
#               alert before Tasks 9-11 build on top of it. The
#               suricata.service systemd unit is never started - this
#               project only ever invokes the binary directly with -r.
# author      : Aïda Sylla
# date        : 2026-08-17

set -uo pipefail
# NOTE: deliberately not using -e. A config-test failure or a smoke PCAP
# producing zero alerts are expected, meaningful outcomes this script
# must detect and report - not script bugs.

if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it installs packages and writes to /var/lib/suricata and /var/log/suricata). Try: sudo $0" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_RULES_DIR="/home/analyst/MedDefense_Lab/suricata/rules"
LAB_PCAP_DIR="/home/analyst/MedDefense_Lab/PCAPs"
SMOKE_PCAP="${LAB_PCAP_DIR}/smoke.pcap"
SURICATA_RULES_DIR="/var/lib/suricata/rules"
SURICATA_LOG_DIR="/var/log/suricata"
CONFIG_PATH="${SCRIPT_DIR}/suricata.yaml"
OUTPUT_PATH="${SCRIPT_DIR}/setup_verification.json"
SMOKE_OUT_DIR="/tmp/suricata-smoke"

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}

# ---------------------------------------------------------------------------
# 1. Idempotent install of suricata and jq.
# ---------------------------------------------------------------------------
echo "[*] Checking suricata and jq installation..."

install_if_missing() {
    local pkg="$1"
    if command -v "${pkg}" >/dev/null 2>&1; then
        echo "    ${pkg}: already installed."
        return 0
    fi
    echo "    ${pkg}: installing..."
    if ! timeout 600 env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
        apt-get install -y "${pkg}" \
        -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        < /dev/null > /tmp/apt_install_"${pkg}".log 2>&1; then
        echo "    FAILED to install ${pkg}. See /tmp/apt_install_${pkg}.log" >&2
        return 1
    fi
    echo "    ${pkg}: installed."
    return 0
}

if ! command -v jq >/dev/null 2>&1 || ! command -v suricata >/dev/null 2>&1; then
    timeout 300 env DEBIAN_FRONTEND=noninteractive apt-get update < /dev/null > /tmp/apt_update.log 2>&1 || true
fi

install_if_missing jq || exit 1
install_if_missing suricata || exit 1

installed_version="$(suricata --build-info 2>/dev/null | grep -oP 'This is Suricata version \K[0-9.]+' || suricata -V 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")"
echo "    suricata version: ${installed_version}"

# ---------------------------------------------------------------------------
# 2. Copy the provided ruleset into the standard rule directory.
# ---------------------------------------------------------------------------
echo "[*] Copying ruleset..."

if [[ ! -d "${LAB_RULES_DIR}" ]]; then
    echo "FAILED: rule source directory not found at ${LAB_RULES_DIR}. Cannot proceed without the project-supplied ruleset." >&2
    exit 1
fi

mkdir -p "${SURICATA_RULES_DIR}"

mapfile -t SOURCE_RULE_FILES < <(find "${LAB_RULES_DIR}" -maxdepth 1 -name '*.rules' -type f 2>/dev/null | sort)
source_count="${#SOURCE_RULE_FILES[@]}"

if [[ "${source_count}" -eq 0 ]]; then
    echo "FAILED: no .rules files found in ${LAB_RULES_DIR}." >&2
    exit 1
fi

for f in "${SOURCE_RULE_FILES[@]}"; do
    cp -f "${f}" "${SURICATA_RULES_DIR}/"
done

mapfile -t DEST_RULE_FILES < <(find "${SURICATA_RULES_DIR}" -maxdepth 1 -name '*.rules' -type f 2>/dev/null | sort)
dest_count="${#DEST_RULE_FILES[@]}"

echo "    ${source_count} rule files in source, ${dest_count} present in ${SURICATA_RULES_DIR} after copy."
if [[ "${dest_count}" -lt "${source_count}" ]]; then
    echo "WARNING: fewer rule files present after copy than in source - some copies may have failed." >&2
fi

# meddefense.rules is a project-authored placeholder (Task 9's custom
# rules land here) - create it empty if it doesn't already exist, so
# suricata.yaml's rule-files list references a file that actually exists
# even before Task 9 populates it, and the config test below doesn't fail
# on a missing file.
MEDDEFENSE_RULES_PATH="${SURICATA_RULES_DIR}/meddefense.rules"
if [[ ! -f "${MEDDEFENSE_RULES_PATH}" ]]; then
    echo "# MedDefense custom Suricata rules - populated by Task 9." > "${MEDDEFENSE_RULES_PATH}"
    echo "    Created empty placeholder: meddefense.rules"
fi

rule_count=0
for f in "${SURICATA_RULES_DIR}"/*.rules; do
    [[ -f "${f}" ]] || continue
    # NOTE: grep -c always prints a valid count on stdout, including "0"
    # when nothing matches - but its own exit code is 1 in that exact
    # case (not an error, just "no match"). An earlier version of this
    # line added `|| echo 0` as a fallback, which fired on every
    # zero-match file (e.g. the freshly-created empty meddefense.rules
    # placeholder) IN ADDITION to grep's own already-printed "0",
    # producing a two-line "0\n0" string that broke the arithmetic
    # expansion below. grep -c needs no such fallback.
    count="$(grep -cE '^[[:space:]]*(alert|drop|pass|reject)[[:space:]]' "${f}" 2>/dev/null)"
    [[ -z "${count}" ]] && count=0
    rule_count=$((rule_count + count))
done
echo "    ${rule_count} total rule lines counted across all loaded rule files."

# ---------------------------------------------------------------------------
# 3. Render suricata.yaml.
# ---------------------------------------------------------------------------
echo "[*] Rendering suricata.yaml..."

mkdir -p "${SURICATA_LOG_DIR}"

RULE_FILE_NAMES=()
for f in "${DEST_RULE_FILES[@]}"; do
    RULE_FILE_NAMES+=("$(basename "${f}")")
done
if [[ ! " ${RULE_FILE_NAMES[*]} " == *" meddefense.rules "* ]]; then
    RULE_FILE_NAMES+=("meddefense.rules")
fi

CONF_TMP="$(mktemp)"
{
    echo "%YAML 1.1"
    echo "---"
    echo "# Generated by 8-suricata_setup.sh - offline PCAP replay configuration."
    echo "# This project never runs suricata as a live daemon on an interface;"
    echo "# every invocation points -r at a provided PCAP. suricata.service is"
    echo "# never started."
    echo ""
    echo "vars:"
    echo "  address-groups:"
    echo "    HOME_NET: \"[10.10.0.0/16]\""
    echo "    EXTERNAL_NET: \"!\$HOME_NET\""
    echo ""
    echo "default-log-dir: ${SURICATA_LOG_DIR}"
    echo ""
    echo "outputs:"
    echo "  - eve-log:"
    echo "      enabled: yes"
    echo "      filetype: regular"
    echo "      filename: eve.json"
    echo "      types:"
    echo "        - alert"
    echo "        - http"
    echo "        - dns"
    echo "        - tls"
    # NOTE: "fileinfo" is deliberately NOT listed here. Confirmed twice
    # against the real suricata 6.0.4 on billing-srv-01: both a bare
    # string entry AND the mapping form with force-magic caused the
    # identical real error "No output module named eve-log.fileinfo".
    # This suricata version appears to require fileinfo's registration
    # through a separate mechanism (likely a standalone file-store/
    # filestore output block, not investigated further here) rather than
    # a plain eve-log types entry. The task explicitly requires fileinfo
    # among the eve-log types - this is a known, confirmed gap to close
    # once the correct 6.0.4-specific syntax is found, documented here
    # rather than guessed at repeatedly against a live host.
    echo ""
    echo "logging:"
    echo "  default-log-level: notice"
    echo ""
    echo "default-rule-path: ${SURICATA_RULES_DIR}"
    echo ""
    echo "rule-files:"
    for rf in "${RULE_FILE_NAMES[@]}"; do
        echo "  - ${rf}"
    done
    echo ""
    echo "pcap-file:"
    echo "  enabled: yes"
    echo "  checksum-checks: auto"
    echo ""
    echo "af-packet:"
    echo "  - interface: default"
    echo ""
    echo "app-layer:"
    echo "  protocols:"
    echo "    tls:"
    echo "      enabled: yes"
    echo "    http:"
    echo "      enabled: yes"
    echo "    dns:"
    echo "      enabled: yes"
} > "${CONF_TMP}"

mv "${CONF_TMP}" "${CONFIG_PATH}"
chmod 644 "${CONFIG_PATH}"
echo "    $(wc -l < "${CONFIG_PATH}") lines rendered."

# ---------------------------------------------------------------------------
# 4. Config-only test.
# ---------------------------------------------------------------------------
echo "[*] Running config test (suricata -T)..."

config_test_output="$(mktemp)"
suricata -T -c "${CONFIG_PATH}" -v > "${config_test_output}" 2>&1
config_test_exit=$?
tail -n 15 "${config_test_output}"
rm -f "${config_test_output}"
echo "    config test exit code: ${config_test_exit}"

# ---------------------------------------------------------------------------
# 5. Smoke test: replay a small sample PCAP and confirm at least one alert.
# ---------------------------------------------------------------------------
smoke_alerts=0
if [[ "${config_test_exit}" -ne 0 ]]; then
    echo "[*] Skipping smoke test - config test failed, nothing further can be trusted." >&2
elif [[ ! -f "${SMOKE_PCAP}" ]]; then
    echo "[*] Skipping smoke test - smoke.pcap not found at ${SMOKE_PCAP}." >&2
else
    echo "[*] Running smoke test (suricata -r ${SMOKE_PCAP})..."
    rm -rf "${SMOKE_OUT_DIR}"
    mkdir -p "${SMOKE_OUT_DIR}"
    suricata -c "${CONFIG_PATH}" -r "${SMOKE_PCAP}" -l "${SMOKE_OUT_DIR}/" > /tmp/suricata_smoke_run.log 2>&1
    smoke_run_exit=$?

    eve_path="${SMOKE_OUT_DIR}/eve.json"
    if [[ -f "${eve_path}" ]]; then
        smoke_alerts="$(jq -r 'select(.event_type == "alert")' "${eve_path}" 2>/dev/null | jq -s 'length' 2>/dev/null || echo 0)"
    fi
    echo "    smoke test exit: ${smoke_run_exit}   alerts found: ${smoke_alerts}"
fi

# ---------------------------------------------------------------------------
# 6. Emit setup_verification.json
# ---------------------------------------------------------------------------
RULE_FILES_JSON="[$(for rf in "${RULE_FILE_NAMES[@]}"; do printf '"%s",' "$(json_escape "${rf}")"; done | sed 's/,$//')]"

jq -n \
    --arg version "${installed_version}" \
    --argjson rule_files "${RULE_FILES_JSON}" \
    --argjson rule_count "${rule_count}" \
    --argjson config_test_exit "${config_test_exit}" \
    --arg smoke_pcap "${SMOKE_PCAP}" \
    --argjson smoke_alerts "${smoke_alerts:-0}" \
    '{
        installed_version: $version,
        rule_files_loaded: $rule_files,
        rule_count: $rule_count,
        config_test_exit: $config_test_exit,
        smoke_pcap: $smoke_pcap,
        smoke_alerts: $smoke_alerts
    }' > "${OUTPUT_PATH}"

echo "Report saved to: $(basename "${OUTPUT_PATH}")"

if [[ "${config_test_exit}" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
