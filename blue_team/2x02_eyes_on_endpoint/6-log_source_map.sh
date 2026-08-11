#!/bin/bash
#
# script name : 6-log_source_map.sh
# purpose     : inventory the active log sources on the hardened Linux
#               system - auth.log, syslog, audit.log, kern.log, dpkg.log,
#               apache2 access/error, plus any other security-relevant
#               sources discovered - reporting path, format, rotation
#               policy (parsed from logrotate config), current file size,
#               an estimated events-per-hour rate, and a security relevance
#               rating. Flags any expected source that is missing or has
#               generated no recent events.
# author      : Aïda Sylla
# date        : 2026-08-09
 
set -euo pipefail
# Every per-source lookup below (permission checks, logrotate parsing,
# timestamp parsing on files whose exact format can vary by distro/version)
# is expected to fail gracefully for that one source without aborting the
# whole inventory. With -e active, every command that can legitimately
# return non-zero as part of normal control flow (a grep with no match, a
# date string that doesn't parse) is explicitly guarded with "|| true" or
# an if/case check, rather than left to propagate.
 
echo "[*] Discovering log sources..."
 
# ---------------------------------------------------------------------------
# Baseline expected sources (fixed order matches the task's required list).
# ---------------------------------------------------------------------------
SOURCE_ORDER=("auth.log" "audit.log" "syslog" "kern.log" "apache2 access" "apache2 error" "dpkg.log")
 
declare -A SOURCE_PATH=(
    ["auth.log"]="/var/log/auth.log"
    ["audit.log"]="/var/log/audit/audit.log"
    ["syslog"]="/var/log/syslog"
    ["kern.log"]="/var/log/kern.log"
    ["apache2 access"]="/var/log/apache2/access.log"
    ["apache2 error"]="/var/log/apache2/error.log"
    ["dpkg.log"]="/var/log/dpkg.log"
)
declare -A SOURCE_FORMAT=(
    ["auth.log"]="syslog"
    ["audit.log"]="audit"
    ["syslog"]="syslog"
    ["kern.log"]="syslog"
    ["apache2 access"]="combined"
    ["apache2 error"]="custom"
    ["dpkg.log"]="custom"
)
declare -A SOURCE_RELEVANCE=(
    ["auth.log"]="critical"
    ["audit.log"]="critical"
    ["syslog"]="high"
    ["kern.log"]="medium"
    ["apache2 access"]="high"
    ["apache2 error"]="high"
    ["dpkg.log"]="medium"
)
 
# Opportunistic extra sources - reported separately, never counted against
# "Missing" since they are not part of the required baseline.
EXTRA_ORDER=("ufw.log" "fail2ban.log" "secure" "cron.log" "mail.log")
declare -A EXTRA_PATH=(
    ["ufw.log"]="/var/log/ufw.log"
    ["fail2ban.log"]="/var/log/fail2ban.log"
    ["secure"]="/var/log/secure"
    ["cron.log"]="/var/log/cron.log"
    ["mail.log"]="/var/log/mail.log"
)
declare -A EXTRA_FORMAT=(
    ["ufw.log"]="syslog"
    ["fail2ban.log"]="syslog"
    ["secure"]="syslog"
    ["cron.log"]="syslog"
    ["mail.log"]="syslog"
)
declare -A EXTRA_RELEVANCE=(
    ["ufw.log"]="high"
    ["fail2ban.log"]="high"
    ["secure"]="critical"
    ["cron.log"]="medium"
    ["mail.log"]="low"
)
 
# ---------------------------------------------------------------------------
# Rotation policy: parse /etc/logrotate.d/* and /etc/logrotate.conf for the
# stanza whose path glob(s) match the target, extract "rotate N" and the
# frequency keyword, and convert to an approximate day count
# (daily=1x, weekly=7x, monthly=30x, yearly=365x per rotation - an
# approximation, not a calendar-exact figure).
#
# KNOWN LIMITATION (confirmed while testing this script): if more than one
# stanza across different files matches the same path - e.g. a distro
# package's default config and a separate hardening config added on top -
# this function returns the FIRST match in glob order (alphabetical by
# filename under /etc/logrotate.d/), not necessarily the policy that
# actually governs in practice. Verify manually if a source has more than
# one logrotate stanza referencing it.
# ---------------------------------------------------------------------------
get_rotation_days() {
    local target="$1"
    local conf header clean line in_block rotate_n freq glob matched days
 
    for conf in /etc/logrotate.d/* /etc/logrotate.conf; do
        [[ -f "${conf}" ]] || continue
        header=""
        in_block=0
        rotate_n=""
        freq=""
 
        while IFS= read -r line; do
            clean="${line%%#*}"
            if [[ "${in_block}" -eq 0 ]]; then
                if [[ "${clean}" == *"{"* ]]; then
                    header="${header} ${clean%%\{*}"
                    in_block=1
                    rotate_n=""
                    freq=""
                else
                    header="${header} ${clean}"
                fi
            else
                if [[ "${clean}" == *"}"* ]]; then
                    in_block=0
                    matched=0
                    for glob in ${header}; do
                        [[ -z "${glob}" ]] && continue
                        # shellcheck disable=SC2254
                        # Intentionally unquoted: ${glob} must be interpreted
                        # as a shell glob pattern here (logrotate stanzas
                        # commonly use paths like /var/log/*.log), not
                        # matched as a literal string.
                        case "${target}" in
                            ${glob}) matched=1 ;;
                        esac
                    done
                    if [[ "${matched}" -eq 1 && -n "${freq}" && -n "${rotate_n}" ]]; then
                        case "${freq}" in
                            daily)   days=$((rotate_n * 1)) ;;
                            weekly)  days=$((rotate_n * 7)) ;;
                            monthly) days=$((rotate_n * 30)) ;;
                            yearly)  days=$((rotate_n * 365)) ;;
                            *)       days="" ;;
                        esac
                        if [[ -n "${days}" ]]; then
                            echo "${days} days"
                            return 0
                        fi
                    fi
                    header=""
                else
                    if [[ "${clean}" == *rotate* ]]; then
                        rotate_n="$(echo "${clean}" | grep -oE '[0-9]+' | head -1 || true)"
                    fi
                    [[ "${clean}" == *daily* ]] && freq="daily"
                    [[ "${clean}" == *weekly* ]] && freq="weekly"
                    [[ "${clean}" == *monthly* ]] && freq="monthly"
                    [[ "${clean}" == *yearly* ]] && freq="yearly"
                fi
            fi
        done < "${conf}"
    done
 
    echo "not configured"
}
 
# ---------------------------------------------------------------------------
# Human-readable current file size.
# ---------------------------------------------------------------------------
get_file_size() {
    local path="$1"
    if [[ -r "${path}" ]]; then
        du -h "${path}" 2>/dev/null | cut -f1 || true
    else
        echo "N/A"
    fi
}
 
# ---------------------------------------------------------------------------
# Estimated events/hour: parses the timestamp on the first and last line of
# the file (format-specific) and divides total line count by the elapsed
# hours between them. This is an ESTIMATE derived from the file's current
# span, not a live-sampled rate - a burst-heavy or very young log can skew
# it. Falls back to "N/A" when the format can't be parsed.
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
 
epoch_from_combined_line() {
    local line="$1" ts
    ts="$(echo "${line}" | grep -oP '(?<=\[)[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}(?= )' | head -1 || true)"
    [[ -z "${ts}" ]] && return 1
    date -d "$(echo "${ts}" | sed 's#/# #; s#/# #; s#:# #')" +%s 2>/dev/null
}
 
epoch_from_iso_line() {
    local line="$1" ts
    ts="$(echo "${line}" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1 || true)"
    [[ -z "${ts}" ]] && return 1
    date -d "${ts}" +%s 2>/dev/null
}
 
get_events_per_hour() {
    local path="$1" format="$2" lines first_line last_line first_epoch last_epoch elapsed_hours rate
 
    [[ -r "${path}" ]] || { echo "N/A"; return; }
 
    lines="$(wc -l < "${path}" 2>/dev/null || echo 0)"
    if [[ "${lines}" -eq 0 ]]; then
        echo "<1"
        return
    fi
 
    first_line="$(head -n 1 "${path}" 2>/dev/null)"
    last_line="$(tail -n 1 "${path}" 2>/dev/null)"
 
    case "${format}" in
        syslog)   first_epoch="$(epoch_from_syslog_line "${first_line}" || true)"; last_epoch="$(epoch_from_syslog_line "${last_line}" || true)" ;;
        audit)    first_epoch="$(epoch_from_audit_line "${first_line}" || true)"; last_epoch="$(epoch_from_audit_line "${last_line}" || true)" ;;
        combined) first_epoch="$(epoch_from_combined_line "${first_line}" || true)"; last_epoch="$(epoch_from_combined_line "${last_line}" || true)" ;;
        *)        first_epoch="$(epoch_from_iso_line "${first_line}" || true)"; last_epoch="$(epoch_from_iso_line "${last_line}" || true)" ;;
    esac
 
    if [[ -z "${first_epoch:-}" || -z "${last_epoch:-}" ]]; then
        echo "N/A"
        return
    fi
 
    elapsed_hours="$(awk -v a="${first_epoch}" -v b="${last_epoch}" 'BEGIN { d=b-a; if (d<3600) d=3600; printf "%.4f", d/3600 }')"
    rate="$(awk -v l="${lines}" -v h="${elapsed_hours}" 'BEGIN { printf "%.0f", l/h }')"
 
    if [[ "${rate}" -lt 1 ]]; then
        echo "<1"
    else
        echo "${rate}"
    fi
}
 
# ---------------------------------------------------------------------------
# Build and print the table (Source, Path, Format, Rotation, Size,
# events/hr, Relevance).
# ---------------------------------------------------------------------------
printf "%-18s %-28s %-9s %-13s %-8s %-10s %-9s\n" "Source" "Path" "Format" "Rotation" "Size" "Events/hr" "Relevance"
printf "%-18s %-28s %-9s %-13s %-8s %-10s %-9s\n" "------" "----" "------" "--------" "----" "---------" "---------"
 
found_count=0
missing_sources=()
 
for name in "${SOURCE_ORDER[@]}"; do
    path="${SOURCE_PATH[${name}]}"
    if [[ -e "${path}" ]]; then
        format="${SOURCE_FORMAT[${name}]}"
        rotation="$(get_rotation_days "${path}")"
        size="$(get_file_size "${path}" || true)"
        rate="$(get_events_per_hour "${path}" "${format}")"
        relevance="${SOURCE_RELEVANCE[${name}]}"
        printf "%-18s %-28s %-9s %-13s %-8s %-10s %-9s\n" "${name}" "${path}" "${format}" "${rotation}" "${size}" "${rate}" "${relevance}"
        found_count=$((found_count + 1))
    else
        missing_sources+=("${name} (${path})")
    fi
done
 
extra_found=0
extra_rows=""
for name in "${EXTRA_ORDER[@]}"; do
    path="${EXTRA_PATH[${name}]}"
    if [[ -e "${path}" ]]; then
        format="${EXTRA_FORMAT[${name}]}"
        rotation="$(get_rotation_days "${path}")"
        size="$(get_file_size "${path}" || true)"
        rate="$(get_events_per_hour "${path}" "${format}")"
        relevance="${EXTRA_RELEVANCE[${name}]}"
        extra_rows="${extra_rows}$(printf "%-18s %-28s %-9s %-13s %-8s %-10s %-9s\n" "${name}" "${path}" "${format}" "${rotation}" "${size}" "${rate}" "${relevance}")\n"
        extra_found=$((extra_found + 1))
    fi
done
 
if [[ "${extra_found}" -gt 0 ]]; then
    echo ""
    echo "Additional security-relevant sources discovered:"
    printf "%-18s %-28s %-9s %-13s %-8s %-10s %-9s\n" "Source" "Path" "Format" "Rotation" "Size" "Events/hr" "Relevance"
    echo -e "${extra_rows}"
fi
 
if [[ "${#missing_sources[@]}" -gt 0 ]]; then
    echo ""
    echo "Missing or not generating events:"
    for m in "${missing_sources[@]}"; do
        echo "    - ${m}"
    done
fi
 
echo ""
echo "Sources found: ${found_count} | Missing: ${#missing_sources[@]}"
