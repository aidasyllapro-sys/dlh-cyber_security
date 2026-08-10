#!/bin/bash
#
# script name : 5-auditd_refine.sh
# purpose     : refine the 2x00 auditd baseline by adding detection-focused
#               rules for process execution (execve), network socket
#               creation, SSH key file access, cron directory modification,
#               and sudoers.d access, then validate each new rule actually
#               fires by triggering a real test action and searching for it
#               with ausearch.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
 
# A dedicated rules file, separate from the 2x00 meddefense.rules baseline,
# so this task's additions never risk overwriting or reordering the
# identity/privilege-escalation/tool-execution rules already in place.
RULES_FILE="/etc/audit/rules.d/meddefense-detection.rules"
 
TEST_SSH_FILE="${HOME}/.ssh/test_auditd_refine"
TEST_CRON_FILE="/etc/cron.d/test_auditd_refine"
TEST_SUDOERS_FILE="/etc/sudoers.d/test_auditd_refine"
 
cleanup() {
    rm -f "${TEST_SSH_FILE}" "${TEST_CRON_FILE}" "${TEST_SUDOERS_FILE}" 2>/dev/null || true
}
trap cleanup EXIT
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it manages auditd rules and writes under /etc/audit/, /etc/cron.d/, /etc/sudoers.d/). Try: sudo ${0}" >&2
    exit 1
fi
 
if ! command -v auditctl >/dev/null 2>&1; then
    echo "auditctl not found. Is auditd installed?" >&2
    exit 1
fi
 
if ! command -v augenrules >/dev/null 2>&1; then
    echo "augenrules not found. Is the audit package fully installed?" >&2
    exit 1
fi
 
current_rule_count() {
    auditctl -l 2>/dev/null | grep -c . || true
}
 
initial_count="$(current_rule_count)"
echo "[*] Current auditd rules: ${initial_count}"
 
echo "[*] Adding detection-focused rules..."
 
mkdir -p "$(dirname "${RULES_FILE}")"
[[ -f "${RULES_FILE}" ]] || touch "${RULES_FILE}"
 
# Each entry: "label:::rule_lines" - rule_lines may contain more than one
# newline-separated auditctl rule definition. The cron category watches two
# separate paths under the same key, reported here as a single [ADDED] item.
RULE_ENTRIES=(
    "execve syscall tracking:::-a always,exit -F arch=b64 -S execve -k process_exec"
    "socket/connect syscall tracking:::-a always,exit -F arch=b64 -S socket -S connect -k network_connect"
    "SSH key file monitoring:::-w /home/*/.ssh/ -p rwa -k ssh_keys"
    $'Cron directory monitoring:::-w /etc/cron.d/ -p wa -k cron_persist\n-w /var/spool/cron/ -p wa -k cron_persist'
    "sudoers.d monitoring:::-w /etc/sudoers.d/ -p wa -k sudoers"
)
 
rules_added_count=0
 
for entry in "${RULE_ENTRIES[@]}"; do
    label="${entry%%:::*}"
    rule_lines="${entry#*:::}"
 
    entry_added=false
    while IFS= read -r rule_line; do
        [[ -z "${rule_line}" ]] && continue
        if ! grep -qF -- "${rule_line}" "${RULES_FILE}" 2>/dev/null; then
            echo "${rule_line}" >> "${RULES_FILE}"
            entry_added=true
        fi
    done <<< "${rule_lines}"
 
    if [[ "${entry_added}" == true ]]; then
        printf "    %-38s [ADDED]\n" "${label}"
        rules_added_count=$((rules_added_count + 1))
    else
        printf "    %-38s [SKIPPED - already present]\n" "${label}"
    fi
done
 
echo "[*] Loading rules..."
if augenrules --load >/tmp/auditd_refine_load.log 2>&1; then
    echo "    augenrules --load: OK"
else
    echo "    augenrules --load: FAILED"
    cat /tmp/auditd_refine_load.log >&2
    exit 1
fi
 
final_count="$(current_rule_count)"
echo "[*] Total rules: ${final_count}"
 
echo "[*] Validating new rules..."
 
validation_pass=0
validation_total=5
 
# Runs "$@" as the test action, then searches ausearch for a matching event
# under search_key. "-ts recent" is ausearch's own built-in time keyword,
# covering roughly the last 10 minutes (see man ausearch) - simpler and less
# error-prone than hand-formatting a timestamp across a possible midnight
# rollover.
validate_rule() {
    local description="$1"
    local search_key="$2"
    local display_cmd="$3"
    shift 3
 
    "$@" >/dev/null 2>&1 || true
    sleep 1
 
    if ausearch -k "${search_key}" -ts recent 2>/dev/null | grep -q .; then
        printf "    %-55s [CAPTURED]\n" "${description}: ${display_cmd} -> ausearch -k ${search_key}"
        return 0
    fi
    printf "    %-55s [MISSED]\n" "${description}: ${display_cmd} -> ausearch -k ${search_key}"
    return 1
}
 
if validate_rule "execve" "process_exec" "ran /usr/bin/id" /usr/bin/id; then
    validation_pass=$((validation_pass + 1))
fi
 
if command -v curl >/dev/null 2>&1; then
    if validate_rule "socket" "network_connect" "curl localhost" curl -s --max-time 2 "http://localhost/"; then
        validation_pass=$((validation_pass + 1))
    fi
else
    printf "    %-55s [MISSED - curl not installed]\n" "socket: curl localhost -> ausearch -k network_connect"
fi
 
mkdir -p "${HOME}/.ssh"
if validate_rule "ssh_keys" "ssh_keys" "touch ~/.ssh/test" touch "${TEST_SSH_FILE}"; then
    validation_pass=$((validation_pass + 1))
fi
 
if validate_rule "cron" "cron_persist" "touch /etc/cron.d/test" touch "${TEST_CRON_FILE}"; then
    validation_pass=$((validation_pass + 1))
fi
 
if validate_rule "sudoers" "sudoers" "touch /etc/sudoers.d/test" touch "${TEST_SUDOERS_FILE}"; then
    validation_pass=$((validation_pass + 1))
fi
 
echo "Rules added: ${rules_added_count} | Validation: ${validation_pass}/${validation_total} PASS"
