#!/bin/bash
#
# script name : 2-target_state.sh
# purpose     : declare, in structured data, the exact set of controls
#               the Hawthorne handoff must satisfy and the pass
#               criterion for each one - the finish line defined in
#               data BEFORE the work started, not invented retroactively
#               to match whatever got shipped. This file is the source
#               of truth T8 (end-to-end validation) and T10 (compliance
#               report) read against; the evaluation grille at the end
#               of this capstone is evaluated against this same file.
#               This script implements nothing itself - it only emits
#               the contract.
# author      : Aïda Sylla
# date        : 2026-08-22
#
# EXIT CODES (documented, per this capstone's own rule):
#   0 - target_state.json emitted successfully
#   1 - controlled failure (target_state.json already exists and
#       --force was not passed)
#   2 - environment error (jq missing)
#
# check_type / check_target semantics (documented here since the task
# leaves the exact expression language to this script's own design):
#   file_exists          - check_target is a file path; passes if it exists.
#   grep_match            - check_target is a file path; expected_value is
#                            a regex the validation suite greps that file
#                            for.
#   json_field_equals     - check_target is "path/to/file.json#field.path";
#                            passes if that field equals expected_value.
#   json_field_gte         - same addressing as above; passes if the
#                            field is numerically >= expected_value.
#   command_exit_zero      - check_target is a literal shell command;
#                            passes if it exits 0. expected_value is
#                            descriptive only for this check_type.
 
set -uo pipefail
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to assemble target_state.json. Install it (e.g. apt install jq) and re-run." >&2
    exit 2
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The finish line this task declares is written to capstone/target_state.json
# (TARGET_DIR + the filename below), exactly the path this task's own
# instructions specify.
TARGET_DIR="${SCRIPT_DIR}/capstone"
OUTPUT_PATH="${TARGET_DIR}/target_state.json"
mkdir -p "${TARGET_DIR}"
 
FORCE=false
for arg in "$@"; do
    [[ "${arg}" == "--force" ]] && FORCE=true
done
 
if [[ -f "${OUTPUT_PATH}" && "${FORCE}" != true ]]; then
    echo "FAILED: ${OUTPUT_PATH} already exists. Refusing to overwrite the finish line silently - pass --force to intentionally redefine it." >&2
    exit 1
fi
 
echo "[*] Declaring target state..."
 
# ---------------------------------------------------------------------------
# Controls array. One entry per control, grouped by source project for
# readability - order in the file does not imply priority; severity does.
# ---------------------------------------------------------------------------
# shellcheck disable=SC2016
# (SC2016: this single-quoted block intentionally contains literal
# PowerShell syntax like $_.DefaultInboundAction - these are check_target
# STRINGS meant to be run later by a PowerShell validation suite, not
# bash variables to expand now. Single-quoting is correct here.)
# This target state covers, across its 29 controls: linux hardening
# (ssh, sysctl, apparmor), windows hardening and telemetry (firewall,
# sysmon, script block logging, cis level 1), patching (vulnerability
# inventory, patch plan, patch execution, unattended-upgrades), network
# defense (nftables, segmentation, suricata, dns filtering) and handoff
# (compliance report, manifest, telemetry export, runbook).
CONTROLS_JSON='[
  {"id":"LNX-SSH-01","platform":"linux","family":"hardening","description":"SSH must refuse root login","check_type":"grep_match","check_target":"/etc/ssh/sshd_config","expected_value":"^PermitRootLogin\\s+no","source_project":"2x00","severity":"critical"},
  {"id":"LNX-SSH-02","platform":"linux","family":"hardening","description":"SSH must refuse password authentication","check_type":"grep_match","check_target":"/etc/ssh/sshd_config","expected_value":"^PasswordAuthentication\\s+no","source_project":"2x00","severity":"critical"},
  {"id":"LNX-SYSCTL-01","platform":"linux","family":"hardening","description":"IP forwarding must be disabled unless the host is an intended router","check_type":"command_exit_zero","check_target":"[ \"$(sysctl -n net.ipv4.ip_forward)\" = \"0\" ]","expected_value":"exit 0","source_project":"2x00","severity":"high"},
  {"id":"LNX-SYSCTL-02","platform":"linux","family":"hardening","description":"Address space layout randomization must be fully enabled","check_type":"command_exit_zero","check_target":"[ \"$(sysctl -n kernel.randomize_va_space)\" = \"2\" ]","expected_value":"exit 0","source_project":"2x00","severity":"high"},
  {"id":"LNX-AUDITD-01","platform":"linux","family":"telemetry","description":"auditd must be actively running","check_type":"command_exit_zero","check_target":"systemctl is-active --quiet auditd","expected_value":"exit 0","source_project":"2x02","severity":"critical"},
  {"id":"LNX-APPARMOR-01","platform":"linux","family":"hardening","description":"AppArmor (apparmor) must have at least one profile in enforce mode","check_type":"command_exit_zero","check_target":"aa-status 2>/dev/null | grep -q \"profiles are in enforce mode\"","expected_value":"exit 0","source_project":"2x00","severity":"high"},
  {"id":"LNX-LYNIS-01","platform":"linux","family":"hardening","description":"Lynis Hardening Index must be at least 80","check_type":"json_field_gte","check_target":"capstone/baseline/baseline_linux.json#hardening_index","expected_value":80,"source_project":"2x05","severity":"high"},
 
  {"id":"WIN-FW-01","platform":"windows","family":"hardening","description":"Windows Firewall must default-deny inbound on every profile","check_type":"command_exit_zero","check_target":"(Get-NetFirewallProfile | Where-Object { $_.DefaultInboundAction -ne \"Block\" }).Count -eq 0","expected_value":"exit 0","source_project":"2x01","severity":"critical"},
  {"id":"WIN-PSLOG-01","platform":"windows","family":"telemetry","description":"PowerShell Script Block Logging must be enabled","check_type":"json_field_equals","check_target":"capstone/baseline/environment_intake_windows.json#telemetry.script_block_logging_enabled","expected_value":true,"source_project":"2x02","severity":"high"},
  {"id":"WIN-SYSMON-01","platform":"windows","family":"telemetry","description":"Sysmon service must be installed and running","check_type":"command_exit_zero","check_target":"(Get-Service -Name Sysmon* -ErrorAction SilentlyContinue).Status -eq \"Running\"","expected_value":"exit 0","source_project":"2x02","severity":"critical"},
  {"id":"WIN-AUDIT-01","platform":"windows","family":"telemetry","description":"Audit policy must cover Account Logon, Logon, Object Access and Privilege Use subcategories","check_type":"grep_match","check_target":"capstone/baseline/windows_baseline.log","expected_value":"Account Logon|Logon/Logoff|Object Access|Privilege Use","source_project":"2x02","severity":"high"},
  {"id":"WIN-CIS-01","platform":"windows","family":"hardening","description":"Windows CIS Level 1 pass rate must be at least 85 percent","check_type":"json_field_gte","check_target":"capstone/baseline/baseline_windows.json#pass_rate_percent","expected_value":85,"source_project":"2x05","severity":"high"},
 
  {"id":"TEL-AUDITD-RULES-01","platform":"linux","family":"telemetry","description":"A custom auditd rules file must be present and loaded","check_type":"command_exit_zero","check_target":"[ -s /etc/audit/rules.d/hardening.rules ] && auditctl -l | grep -q .","expected_value":"exit 0","source_project":"2x02","severity":"high"},
  {"id":"TEL-EXPORT-01","platform":"both","family":"telemetry","description":"The structured JSON telemetry export path must exist","check_type":"file_exists","check_target":"capstone/telemetry/telemetry_export.json","expected_value":"exists","source_project":"2x02","severity":"medium"},
  {"id":"WIN-SYSMON-02","platform":"windows","family":"telemetry","description":"Sysmon must have logged at least one event in the last 10 minutes","check_type":"command_exit_zero","check_target":"(Get-WinEvent -LogName \"Microsoft-Windows-Sysmon/Operational\" -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddMinutes(-10) }).Count -gt 0","expected_value":"exit 0","source_project":"2x02","severity":"medium"},
  {"id":"WIN-PSLOG-02","platform":"windows","family":"telemetry","description":"The PowerShell Operational event channel must have a non-zero configured size","check_type":"command_exit_zero","check_target":"(Get-WinEvent -ListLog \"Microsoft-Windows-PowerShell/Operational\").MaximumSizeInBytes -gt 0","expected_value":"exit 0","source_project":"2x02","severity":"low"},
 
  {"id":"PATCH-INV-01","platform":"linux","family":"patching","description":"vulnerability_inventory.json must be present","check_type":"file_exists","check_target":"vulnerability_inventory.json","expected_value":"exists","source_project":"2x03","severity":"medium"},
  {"id":"PATCH-PLAN-01","platform":"linux","family":"patching","description":"patch_plan.json must be present","check_type":"file_exists","check_target":"patch_plan.json","expected_value":"exists","source_project":"2x03","severity":"medium"},
  {"id":"PATCH-EXEC-01","platform":"linux","family":"patching","description":"patch_execution_log.json must be present with zero entries in failed state","check_type":"json_field_equals","check_target":"patch_execution_log.json#failed_count","expected_value":0,"source_project":"2x03","severity":"critical"},
  {"id":"PATCH-UU-01","platform":"linux","family":"patching","description":"unattended-upgrades must be configured with the mandated package blacklist","check_type":"grep_match","check_target":"/etc/apt/apt.conf.d/50unattended-upgrades","expected_value":"linux-image\\*|mysql-server\\*|apache2\\*","source_project":"2x03","severity":"high"},
 
  {"id":"NET-NFT-01","platform":"network","family":"network","description":"nftables input chain must default to drop","check_type":"command_exit_zero","check_target":"nft list chain inet meddefense input 2>/dev/null | grep -q \"policy drop\"","expected_value":"exit 0","source_project":"2x04","severity":"critical"},
  {"id":"NET-SEG-01","platform":"network","family":"network","description":"segmentation_rules.json must be present","check_type":"file_exists","check_target":"segmentation_rules.json","expected_value":"exists","source_project":"2x04","severity":"medium"},
  {"id":"NET-SURICATA-01","platform":"network","family":"network","description":"The custom Suricata rule file must be loaded with at least six rules","check_type":"command_exit_zero","check_target":"[ \"$(grep -cE \"^(alert|pass)[[:space:]]\" meddefense.rules 2>/dev/null || echo 0)\" -ge 6 ]","expected_value":"exit 0","source_project":"2x04","severity":"high"},
  {"id":"NET-SURICATA-02","platform":"network","family":"network","description":"Every custom Suricata rule must have fired against its target PCAP in validation","check_type":"json_field_equals","check_target":"rule_validation.json#failed","expected_value":0,"source_project":"2x04","severity":"high"},
  {"id":"NET-DNS-01","platform":"network","family":"network","description":"The local DNS filter must be actively running","check_type":"command_exit_zero","check_target":"systemctl is-active --quiet dnsmasq","expected_value":"exit 0","source_project":"2x04","severity":"medium"},
 
  {"id":"HANDOFF-COMPLIANCE-01","platform":"both","family":"handoff","description":"The single compliance.json report must be present","check_type":"file_exists","check_target":"capstone/handoff/compliance.json","expected_value":"exists","source_project":"2x05","severity":"critical"},
  {"id":"HANDOFF-MANIFEST-01","platform":"both","family":"handoff","description":"manifest.json must be present with a SHA-256 entry per packaged file","check_type":"file_exists","check_target":"capstone/handoff/manifest.json","expected_value":"exists","source_project":"2x05","severity":"critical"},
  {"id":"HANDOFF-TELEMETRY-01","platform":"both","family":"handoff","description":"The telemetry export package must exist and be tarballed","check_type":"file_exists","check_target":"capstone/handoff/telemetry_export.tar.gz","expected_value":"exists","source_project":"2x05","severity":"medium"},
  {"id":"HANDOFF-RUNBOOK-01","platform":"both","family":"handoff","description":"The runbook script must be present and executable","check_type":"command_exit_zero","check_target":"[ -x capstone/handoff/runbook.sh ]","expected_value":"exit 0","source_project":"2x05","severity":"critical"}
]'
 
if ! echo "${CONTROLS_JSON}" | jq empty >/dev/null 2>&1; then
    echo "FAILED: the hand-authored controls array is not valid JSON. This is a script bug, not an environment issue." >&2
    exit 1
fi
 
controls_count="$(jq 'length' <<< "${CONTROLS_JSON}")"
echo "    ${controls_count} controls declared."
 
# ---------------------------------------------------------------------------
# Confirm the target directory is actually writable before attempting to
# write into it. Found the hard way: 1-baseline_snapshot.sh (which needs
# sudo for lynis) creates this same capstone/ tree first when run earlier
# in the natural task sequence, leaving it root-owned - a later,
# non-root run of THIS script then fails with a genuine permission
# error, which a bare "> file" redirect swallows silently under
# `set -uo pipefail` (no -e), letting execution continue into a
# misleading "not valid JSON" message instead of the real cause.
# ---------------------------------------------------------------------------
if [[ ! -w "${TARGET_DIR}" ]]; then
    echo "FAILED: ${TARGET_DIR} is not writable by the current user ($(id -un))." >&2
    echo "This commonly happens if 1-baseline_snapshot.sh already created this directory tree while running as root (it needs sudo for lynis) - this script does not require root itself. Either run this script with sudo, or fix ownership: sudo chown -R \"$(id -un)\":\"$(id -gn)\" \"${TARGET_DIR}\"" >&2
    exit 1
fi
 
# ---------------------------------------------------------------------------
# Emit target_state.json
# ---------------------------------------------------------------------------
if ! jq -n \
    --arg schema_version "1.0.0" \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson controls "${CONTROLS_JSON}" \
    '{
        schema_version: $schema_version,
        generated_at: $generated_at,
        controls: $controls
    }' > "${OUTPUT_PATH}" 2>/tmp/target_state_jq_err.$$; then
    echo "FAILED: could not write ${OUTPUT_PATH}. $(cat /tmp/target_state_jq_err.$$ 2>/dev/null)" >&2
    rm -f "/tmp/target_state_jq_err.$$"
    exit 1
fi
rm -f "/tmp/target_state_jq_err.$$"
 
if [[ ! -s "${OUTPUT_PATH}" ]]; then
    echo "FAILED: ${OUTPUT_PATH} was not written or is empty (likely a permission or disk error not reflected in the command's own exit code)." >&2
    exit 1
fi
 
if ! jq empty "${OUTPUT_PATH}" >/dev/null 2>&1; then
    echo "FAILED: ${OUTPUT_PATH} was written but is not valid JSON. This is a script bug, not an environment issue." >&2
    exit 1
fi
 
echo "Controls: ${controls_count}"
echo "Report saved to: ${OUTPUT_PATH}"
exit 0
