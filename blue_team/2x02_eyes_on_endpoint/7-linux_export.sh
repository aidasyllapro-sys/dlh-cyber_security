#!/bin/bash
#
# script name : 7-linux_export.sh
# purpose     : parse auth.log (SSH logins, sudo, su, generic PAM), audit.log
#               (execve, file access, network socket creation) and syslog
#               (service start/stop, error conditions) over a defined time
#               window, normalize every event to a common schema (ISO 8601
#               UTC timestamp, hostname, source_type, event_category) with
#               category-specific enrichment fields, and export the result
#               to linux_events_export.json - the Linux counterpart to the
#               Windows export from 3-windows_telemetry_export.ps1, meant to
#               be queried with jq.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
 
HOURS_BACK=24
AUTH_LOG="/var/log/auth.log"
AUDIT_LOG="/var/log/audit/audit.log"
SYSLOG_FILE="/var/log/syslog"
OUTPUT_PATH="linux_events_export.json"
 
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours-back) HOURS_BACK="$2"; shift 2 ;;
        --auth-log)   AUTH_LOG="$2"; shift 2 ;;
        --audit-log)  AUDIT_LOG="$2"; shift 2 ;;
        --syslog)     SYSLOG_FILE="$2"; shift 2 ;;
        --output)     OUTPUT_PATH="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done
 
HOSTNAME_VAL="$(hostname)"
NOW_EPOCH="$(date +%s)"
SINCE_EPOCH=$((NOW_EPOCH - HOURS_BACK * 3600))
 
EVENTS_FILE="$(mktemp)"
trap 'rm -f "${EVENTS_FILE}"' EXIT
 
EARLIEST_EPOCH=""
LATEST_EPOCH=""
 
# ---------------------------------------------------------------------------
# JSON helpers (no jq dependency for generation - this script only needs to
# PRODUCE valid JSON; jq is the tool the analyst uses to CONSUME it
# downstream). Escaping covers the characters realistically found in syslog/
# audit lines (backslash, double quote, tab, CR, LF) - not a full RFC 8259
# control-character sweep, which is a deliberate scope simplification for
# this exercise, not a claim of bulletproof general-purpose JSON encoding.
# ---------------------------------------------------------------------------
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
iso8601_utc() {
    local epoch="$1"
    date -u -d "@${epoch}" +"%Y-%m-%dT%H:%M:%SZ"
}
 
update_time_range() {
    local epoch="$1"
    [[ -z "${epoch}" ]] && return 0
    if [[ -z "${EARLIEST_EPOCH}" || "${epoch}" -lt "${EARLIEST_EPOCH}" ]]; then
        EARLIEST_EPOCH="${epoch}"
    fi
    if [[ -z "${LATEST_EPOCH}" || "${epoch}" -gt "${LATEST_EPOCH}" ]]; then
        LATEST_EPOCH="${epoch}"
    fi
}
 
# emit_event <epoch> <source_type> <channel> <category> <raw_message> <enrichment_json_object_body>
# enrichment_json_object_body is a pre-built, already-escaped "key":"value" list.
emit_event() {
    local epoch="$1" source_type="$2" channel="$3" category="$4" raw="$5" enrichment="$6"
    local ts
    ts="$(iso8601_utc "${epoch}")"
    {
        printf '{'
        printf '"timestamp":"%s",' "${ts}"
        printf '"hostname":"%s",' "$(json_escape "${HOSTNAME_VAL}")"
        printf '"platform":"linux",'
        printf '"source_type":"%s",' "$(json_escape "${source_type}")"
        printf '"channel":"%s",' "$(json_escape "${channel}")"
        printf '"event_category":"%s",' "$(json_escape "${category}")"
        printf '"raw_message":"%s"' "$(json_escape "${raw}")"
        if [[ -n "${enrichment}" ]]; then
            printf ',"enrichment":{%s}' "${enrichment}"
        fi
        printf '}\n'
    } >> "${EVENTS_FILE}"
    update_time_range "${epoch}"
}
 
# ---------------------------------------------------------------------------
# Timestamp parsing helpers (same convention as 6-log_source_map.sh)
# ---------------------------------------------------------------------------
epoch_from_syslog_line() {
    local line="$1" mon day time
    read -r mon day time _ <<< "${line}"
    [[ -z "${mon}" || -z "${day}" || -z "${time}" ]] && return 1
    date -d "${mon} ${day} ${time}" +%s 2>/dev/null
}
 
epoch_from_audit_line() {
    local line="$1"
    echo "${line}" | grep -oP 'msg=audit\(\K[0-9]+' | head -1 || true
}
 
kv_field() {
    # kv_field <line> <key>=  -> extracts the value token after key= up to
    # the next whitespace (handles the common "key=value" auth.log/audit
    # token style; does not attempt full shell-quote-aware parsing).
    local line="$1" key="$2"
    echo "${line}" | grep -oP "(?<=${key}=)[^ ]+" | head -1 || true
}
 
# ---------------------------------------------------------------------------
# 1. auth.log
# ---------------------------------------------------------------------------
ssh_count=0
sudo_count=0
su_count=0
pam_count=0
 
if [[ -r "${AUTH_LOG}" ]]; then
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        epoch="$(epoch_from_syslog_line "${line}" || true)"
        [[ -n "${epoch}" && "${epoch}" -lt "${SINCE_EPOCH}" ]] && continue
 
        if echo "${line}" | grep -qE 'sshd\[[0-9]+\]:.*(Accepted|Failed password|Failed publickey)'; then
            user="$(echo "${line}" | grep -oP '(?<=for )(invalid user )?\K[^ ]+' | head -1 || true)"
            src_ip="$(echo "${line}" | grep -oP '(?<=from )[0-9.]+' | head -1 || true)"
            result="failure"
            echo "${line}" | grep -q "Accepted" && result="success"
            enrichment="\"user\":\"$(json_escape "${user}")\",\"source_ip\":\"$(json_escape "${src_ip}")\",\"result\":\"${result}\""
            emit_event "${epoch:-${NOW_EPOCH}}" "auth" "${AUTH_LOG}" "ssh_login" "${line}" "${enrichment}"
            ssh_count=$((ssh_count + 1))
 
        elif echo "${line}" | grep -qE '\bsudo(\[[0-9]+\])?:'; then
            user="$(echo "${line}" | sed -n 's/^.*sudo\(\[[0-9]*\]\)\?: *\([^ ]*\) :.*/\2/p')"
            target_user="$(kv_field "${line}" "USER")"
            command="$(echo "${line}" | grep -oP '(?<=COMMAND=).*' | head -1 || true)"
            enrichment="\"user\":\"$(json_escape "${user}")\",\"target_user\":\"$(json_escape "${target_user}")\",\"command\":\"$(json_escape "${command}")\""
            emit_event "${epoch:-${NOW_EPOCH}}" "auth" "${AUTH_LOG}" "sudo" "${line}" "${enrichment}"
            sudo_count=$((sudo_count + 1))
 
        elif echo "${line}" | grep -qE '\bsu(\[[0-9]+\])?:.*(Successful su|FAILED su)'; then
            result="failure"
            echo "${line}" | grep -q "Successful su" && result="success"
            actor="$(echo "${line}" | grep -oP '(?<=by )[^ ]+' | head -1 || true)"
            target_user="$(echo "${line}" | grep -oP '(?<=su for )[^ ]+' | head -1 || true)"
            enrichment="\"user\":\"$(json_escape "${actor}")\",\"target_user\":\"$(json_escape "${target_user}")\",\"result\":\"${result}\""
            emit_event "${epoch:-${NOW_EPOCH}}" "auth" "${AUTH_LOG}" "su" "${line}" "${enrichment}"
            su_count=$((su_count + 1))
 
        elif echo "${line}" | grep -q "pam_unix"; then
            emit_event "${epoch:-${NOW_EPOCH}}" "auth" "${AUTH_LOG}" "pam" "${line}" ""
            pam_count=$((pam_count + 1))
        fi
    done < "${AUTH_LOG}"
fi
 
auth_total=$((ssh_count + sudo_count + su_count + pam_count))
echo "[*] Parsing auth.log... ${auth_total} events"
echo "    SSH logins: ${ssh_count} | sudo: ${sudo_count} | su: ${su_count} | PAM: ${pam_count}"
 
# ---------------------------------------------------------------------------
# 2. audit.log
#    NOTE: a real auditd event is often SEVERAL lines (SYSCALL, PATH,
#    EXECVE, PROCTITLE...) sharing one msg=audit(id). This script
#    categorizes line-by-line by record type rather than correlating full
#    multi-line events - a deliberate scope simplification for this
#    exercise. execve is read from EXECVE records, file access from PATH
#    records, network activity from SOCKADDR records; everything else in
#    audit.log falls into "other".
# ---------------------------------------------------------------------------
execve_count=0
file_access_count=0
network_count=0
audit_other_count=0
 
if [[ -r "${AUDIT_LOG}" ]]; then
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        epoch="$(epoch_from_audit_line "${line}" || true)"
        [[ -n "${epoch}" && "${epoch}" -lt "${SINCE_EPOCH}" ]] && continue
 
        if echo "${line}" | grep -q "type=EXECVE"; then
            cmdline="$(echo "${line}" | grep -oP '(?<=a0=")[^"]*' | head -1 || true)"
            enrichment="\"command_line\":\"$(json_escape "${cmdline}")\""
            emit_event "${epoch:-${NOW_EPOCH}}" "audit" "${AUDIT_LOG}" "execve" "${line}" "${enrichment}"
            execve_count=$((execve_count + 1))
 
        elif echo "${line}" | grep -q "type=PATH"; then
            path="$(kv_field "${line}" "name")"
            path="${path//\"/}"
            enrichment="\"path\":\"$(json_escape "${path}")\""
            emit_event "${epoch:-${NOW_EPOCH}}" "audit" "${AUDIT_LOG}" "file_access" "${line}" "${enrichment}"
            file_access_count=$((file_access_count + 1))
 
        elif echo "${line}" | grep -q "type=SOCKADDR"; then
            dest="$(kv_field "${line}" "saddr")"
            enrichment="\"destination\":\"$(json_escape "${dest}")\""
            emit_event "${epoch:-${NOW_EPOCH}}" "audit" "${AUDIT_LOG}" "network" "${line}" "${enrichment}"
            network_count=$((network_count + 1))
 
        else
            emit_event "${epoch:-${NOW_EPOCH}}" "audit" "${AUDIT_LOG}" "other" "${line}" ""
            audit_other_count=$((audit_other_count + 1))
        fi
    done < "${AUDIT_LOG}"
fi
 
audit_total=$((execve_count + file_access_count + network_count + audit_other_count))
echo "[*] Parsing audit.log... ${audit_total} events"
echo "    execve: ${execve_count} | file_access: ${file_access_count} | network: ${network_count} | other: ${audit_other_count}"
 
# ---------------------------------------------------------------------------
# 3. syslog
# ---------------------------------------------------------------------------
service_count=0
error_count=0
syslog_other_count=0
 
if [[ -r "${SYSLOG_FILE}" ]]; then
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        epoch="$(epoch_from_syslog_line "${line}" || true)"
        [[ -n "${epoch}" && "${epoch}" -lt "${SINCE_EPOCH}" ]] && continue
 
        if echo "${line}" | grep -qE 'systemd\[[0-9]+\]:.*(Started|Starting|Stopped|Stopping) '; then
            action="start"
            echo "${line}" | grep -qE '(Stopped|Stopping)' && action="stop"
            service="$(echo "${line}" | sed -E 's/^.*(Started|Starting|Stopped|Stopping) //')"
            enrichment="\"service_name\":\"$(json_escape "${service}")\",\"action\":\"${action}\""
            emit_event "${epoch:-${NOW_EPOCH}}" "syslog" "${SYSLOG_FILE}" "service" "${line}" "${enrichment}"
            service_count=$((service_count + 1))
 
        elif echo "${line}" | grep -qiE 'error|failed|failure|critical'; then
            enrichment="\"message\":\"$(json_escape "${line}")\""
            emit_event "${epoch:-${NOW_EPOCH}}" "syslog" "${SYSLOG_FILE}" "error" "${line}" "${enrichment}"
            error_count=$((error_count + 1))
 
        else
            emit_event "${epoch:-${NOW_EPOCH}}" "syslog" "${SYSLOG_FILE}" "other" "${line}" ""
            syslog_other_count=$((syslog_other_count + 1))
        fi
    done < "${SYSLOG_FILE}"
fi
 
syslog_total=$((service_count + error_count + syslog_other_count))
echo "[*] Parsing syslog... ${syslog_total} events"
echo "    service: ${service_count} | error: ${error_count} | other: ${syslog_other_count}"
 
# ---------------------------------------------------------------------------
# Summary + export
# ---------------------------------------------------------------------------
total_events=$((auth_total + audit_total + syslog_total))
echo "Total events: ${total_events}"
 
if [[ -n "${EARLIEST_EPOCH}" && -n "${LATEST_EPOCH}" ]]; then
    range_start="$(iso8601_utc "${EARLIEST_EPOCH}")"
    range_end="$(iso8601_utc "${LATEST_EPOCH}")"
else
    range_start="$(iso8601_utc "${SINCE_EPOCH}")"
    range_end="$(iso8601_utc "${NOW_EPOCH}")"
fi
echo "Time range: ${range_start} to ${range_end}"
 
{
    printf '{'
    printf '"generated":"%s",' "$(iso8601_utc "${NOW_EPOCH}")"
    printf '"hostname":"%s",' "$(json_escape "${HOSTNAME_VAL}")"
    printf '"hours_back":%s,' "${HOURS_BACK}"
    printf '"time_range":{"start":"%s","end":"%s"},' "${range_start}" "${range_end}"
    printf '"counts":{'
    printf '"auth":{"ssh_login":%s,"sudo":%s,"su":%s,"pam":%s,"total":%s},' \
        "${ssh_count}" "${sudo_count}" "${su_count}" "${pam_count}" "${auth_total}"
    printf '"audit":{"execve":%s,"file_access":%s,"network":%s,"other":%s,"total":%s},' \
        "${execve_count}" "${file_access_count}" "${network_count}" "${audit_other_count}" "${audit_total}"
    printf '"syslog":{"service":%s,"error":%s,"other":%s,"total":%s},' \
        "${service_count}" "${error_count}" "${syslog_other_count}" "${syslog_total}"
    printf '"total":%s' "${total_events}"
    printf '},'
    printf '"events":['
    if [[ -s "${EVENTS_FILE}" ]]; then
        paste -sd, "${EVENTS_FILE}"
    fi
    printf ']'
    printf '}'
} > "${OUTPUT_PATH}"
 
echo "Output: ${OUTPUT_PATH}"
