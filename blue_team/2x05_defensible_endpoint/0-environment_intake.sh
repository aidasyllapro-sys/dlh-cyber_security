#!/bin/bash
#
# script name : 0-environment_intake.sh
# purpose     : capture the complete unhardened baseline of
#               hawthorne-app-01 (Linux) before any hardening action -
#               hostname/kernel/distro, package count, listening
#               sockets, active systemd services, sshd_config as
#               key-value, security-relevant sysctl parameters,
#               SUID/SGID and world-writable file counts, firewall
#               status and telemetry presence (auditd, rsyslog, Sysmon
#               for Linux). Every later capstone task measures its
#               success against the delta between this snapshot and the
#               post-hardening state - this script never changes
#               anything, it only observes and records.
# author      : Aïda Sylla
# date        : 2026-08-22
#
# EXIT CODES (documented, per this capstone's own rule):
#   0 - intake captured successfully
#   1 - controlled failure (not expected for a pure-capture script, but
#       reserved for a future consistency check on the output itself)
#   2 - environment error (a required tool is missing)
 
set -uo pipefail
# NOTE: deliberately not using -e. A missing optional tool (nft, Sysmon
# for Linux), zero SUID binaries, or an empty sshd_config are all
# expected, legitimate states this script must still record faithfully -
# not script bugs. Only a REQUIRED tool being absent is treated as a
# hard environment error (exit 2), handled explicitly below.
 
REQUIRED_TOOLS=(hostname uname dpkg-query systemctl find sysctl jq)
MISSING_TOOLS=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "${tool}" >/dev/null 2>&1 || MISSING_TOOLS+=("${tool}")
done
if [[ "${#MISSING_TOOLS[@]}" -gt 0 ]]; then
    echo "Missing required tool(s): ${MISSING_TOOLS[*]}. Cannot capture a trustworthy intake without them." >&2
    exit 2
fi
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "Warning: not running as root. The SUID/SGID and world-writable file scans, and full sshd_config/sysctl visibility, may be incomplete without full privileges. Try: sudo $0" >&2
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${SCRIPT_DIR}/environment_intake_linux.json"
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
echo "[*] Capturing hawthorne-app-01 environment intake..."
 
# ---------------------------------------------------------------------------
# 1. Hostname, kernel release, distribution and patch level.
# ---------------------------------------------------------------------------
echo "    system identity..."
hostname_val="$(hostname)"
kernel_release="$(uname -r)"
distro_name="unknown"
distro_version="unknown"
if [[ -f /etc/os-release ]]; then
    distro_name="$(grep -oP '^NAME="\K[^"]+' /etc/os-release || echo unknown)"
    distro_version="$(grep -oP '^VERSION_ID="\K[^"]+' /etc/os-release || echo unknown)"
fi
# "Patch level" here means the most recent security-relevant package
# update timestamp available without a network call, per this project's
# own no-internet-dependency convention established since 2x03/2x04:
# the newest modification time among installed .deb metadata is used as
# a local, offline proxy for "how recently was this system patched."
patch_level="$(find /var/lib/dpkg/info -name '*.list' -printf '%T@\n' 2>/dev/null | sort -rn | head -1 | cut -d. -f1 || echo 0)"
[[ -z "${patch_level}" ]] && patch_level=0
patch_level_iso="unknown"
if [[ "${patch_level}" != "0" ]]; then
    patch_level_iso="$(date -u -d "@${patch_level}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo unknown)"
fi
 
# ---------------------------------------------------------------------------
# 2. Installed package count.
# ---------------------------------------------------------------------------
echo "    package count..."
package_count="$(dpkg-query -W 2>/dev/null | wc -l | tr -d ' ')"
[[ -z "${package_count}" ]] && package_count=0
 
# ---------------------------------------------------------------------------
# 3. Listening sockets.
# ---------------------------------------------------------------------------
echo "    listening sockets..."
LISTENING_ENTRIES=()
if command -v ss >/dev/null 2>&1; then
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        proto="$(awk '{print $1}' <<< "${line}")"
        local_addr="$(awk '{print $5}' <<< "${line}")"
        proc_info="$(grep -oP 'users:\(\(\K[^)]*' <<< "${line}" || true)"
        proc_name="$(grep -oP '^"?\K[^",]*' <<< "${proc_info}" || true)"
        pid="$(grep -oP 'pid=\K[0-9]+' <<< "${proc_info}" | head -1 || true)"
        [[ -z "${pid}" ]] && pid="0"
        LISTENING_ENTRIES+=("$(jq -n --arg proto "${proto}" --arg addr "${local_addr}" --arg proc "${proc_name}" --argjson pid "${pid}" \
            '{protocol: $proto, local_address: $addr, process: $proc, pid: $pid}')")
    done < <(ss -tulnpH 2>/dev/null || true)
fi
listening_count="${#LISTENING_ENTRIES[@]}"
LISTENING_JSON="[$(IFS=,; echo "${LISTENING_ENTRIES[*]:-}")]"
echo "        ${listening_count} listening sockets."
 
# ---------------------------------------------------------------------------
# 4. Active systemd services.
# ---------------------------------------------------------------------------
echo "    active systemd services..."
mapfile -t ACTIVE_SERVICES < <(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}' | sort)
active_services_count="${#ACTIVE_SERVICES[@]}"
ACTIVE_SERVICES_JSON="[$(for s in "${ACTIVE_SERVICES[@]}"; do printf '"%s",' "$(json_escape "${s}")"; done | sed 's/,$//')]"
echo "        ${active_services_count} active services."
 
# ---------------------------------------------------------------------------
# 5. Current sshd_config as key-value.
# ---------------------------------------------------------------------------
echo "    sshd_config..."
SSHD_CONFIG_PATH="/etc/ssh/sshd_config"
SSHD_ENTRIES=()
if [[ -f "${SSHD_CONFIG_PATH}" ]]; then
    while IFS= read -r line; do
        line="$(sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//' <<< "${line}")"
        [[ -z "${line}" ]] && continue
        key="$(awk '{print $1}' <<< "${line}")"
        value="$(cut -d' ' -f2- <<< "${line}")"
        SSHD_ENTRIES+=("$(jq -n --arg k "${key}" --arg v "${value}" '{key: $k, value: $v}')")
    done < "${SSHD_CONFIG_PATH}"
fi
SSHD_JSON="[$(IFS=,; echo "${SSHD_ENTRIES[*]:-}")]"
echo "        ${#SSHD_ENTRIES[@]} sshd_config directives."
 
# ---------------------------------------------------------------------------
# 6. Security-relevant sysctl parameters.
# ---------------------------------------------------------------------------
echo "    sysctl security parameters..."
SYSCTL_KEYS=(
    "net.ipv4.ip_forward" "net.ipv4.conf.all.accept_redirects"
    "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.all.accept_source_route"
    "net.ipv4.icmp_echo_ignore_broadcasts" "net.ipv4.tcp_syncookies"
    "kernel.randomize_va_space" "fs.suid_dumpable" "kernel.dmesg_restrict"
    "kernel.kptr_restrict" "net.ipv4.conf.all.rp_filter"
)
SYSCTL_ENTRIES=()
for key in "${SYSCTL_KEYS[@]}"; do
    val="$(sysctl -n "${key}" 2>/dev/null || echo "unavailable")"
    SYSCTL_ENTRIES+=("$(jq -n --arg k "${key}" --arg v "${val}" '{key: $k, value: $v}')")
done
SYSCTL_JSON="[$(IFS=,; echo "${SYSCTL_ENTRIES[*]:-}")]"
 
# ---------------------------------------------------------------------------
# 7. SUID/SGID binaries count.
# ---------------------------------------------------------------------------
echo "    SUID/SGID scan (this can take a while on a full filesystem)..."
suid_sgid_count="$(find / -xdev -perm /6000 -type f 2>/dev/null | wc -l | tr -d ' ')"
[[ -z "${suid_sgid_count}" ]] && suid_sgid_count=0
 
# ---------------------------------------------------------------------------
# 8. World-writable files count.
# ---------------------------------------------------------------------------
echo "    world-writable file scan..."
world_writable_count="$(find / -xdev -perm -0002 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | wc -l | tr -d ' ')"
[[ -z "${world_writable_count}" ]] && world_writable_count=0
 
# ---------------------------------------------------------------------------
# 9. Firewall status.
# ---------------------------------------------------------------------------
echo "    firewall status..."
nft_ruleset_lines=0
nft_available=false
if command -v nft >/dev/null 2>&1; then
    nft_available=true
    nft_ruleset_lines="$(nft list ruleset 2>/dev/null | wc -l | tr -d ' ')"
    [[ -z "${nft_ruleset_lines}" ]] && nft_ruleset_lines=0
fi
 
# ---------------------------------------------------------------------------
# 10. Telemetry presence.
# ---------------------------------------------------------------------------
echo "    telemetry presence..."
auditd_active="false"
systemctl is-active auditd >/dev/null 2>&1 && auditd_active="true"
rsyslog_active="false"
systemctl is-active rsyslog >/dev/null 2>&1 && rsyslog_active="true"
# Sysmon for Linux is a less commonly deployed package than its Windows
# counterpart; its service unit is typically named "sysmon" when
# installed via the official Microsoft package. Absence here is a
# legitimate, expected finding on a fresh unmanaged host like Hawthorne's
# app server - not treated as an error.
sysmon_linux_present="false"
if command -v sysmon >/dev/null 2>&1 || systemctl list-unit-files 2>/dev/null | grep -qi '^sysmon\.service'; then
    sysmon_linux_present="true"
fi
 
# ---------------------------------------------------------------------------
# Emit environment_intake_linux.json
# ---------------------------------------------------------------------------
jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "${hostname_val}" \
    --arg kernel_release "${kernel_release}" \
    --arg distro_name "${distro_name}" \
    --arg distro_version "${distro_version}" \
    --arg patch_level "${patch_level_iso}" \
    --argjson package_count "${package_count}" \
    --argjson listening_sockets "${LISTENING_JSON}" \
    --argjson active_services "${ACTIVE_SERVICES_JSON}" \
    --argjson active_services_count "${active_services_count}" \
    --argjson sshd_config "${SSHD_JSON}" \
    --argjson sysctl_security "${SYSCTL_JSON}" \
    --argjson suid_sgid_count "${suid_sgid_count}" \
    --argjson world_writable_count "${world_writable_count}" \
    --argjson nft_available "${nft_available}" \
    --argjson nft_ruleset_lines "${nft_ruleset_lines}" \
    --argjson auditd_active "${auditd_active}" \
    --argjson rsyslog_active "${rsyslog_active}" \
    --argjson sysmon_linux_present "${sysmon_linux_present}" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        kernel_release: $kernel_release,
        distro_name: $distro_name,
        distro_version: $distro_version,
        patch_level: $patch_level,
        package_count: $package_count,
        listening_sockets: $listening_sockets,
        active_services: $active_services,
        active_services_count: $active_services_count,
        sshd_config: $sshd_config,
        sysctl_security: $sysctl_security,
        suid_sgid_count: $suid_sgid_count,
        world_writable_count: $world_writable_count,
        firewall: { nft_available: $nft_available, ruleset_line_count: $nft_ruleset_lines },
        telemetry: { auditd_active: $auditd_active, rsyslog_active: $rsyslog_active, sysmon_linux_present: $sysmon_linux_present }
    }' > "${OUTPUT_PATH}"
 
# ---------------------------------------------------------------------------
# Controlled-failure check: the intake JSON we just wrote must itself be
# well-formed. All required tools were present (exit 2 already handled
# that), so a malformed output here is a genuine controlled failure of
# the capture logic itself, not a missing dependency - distinct exit
# code 1, per this capstone's own exit-code contract.
# ---------------------------------------------------------------------------
if ! jq empty "${OUTPUT_PATH}" >/dev/null 2>&1; then
    echo "FAILED: environment_intake_linux.json was written but is not valid JSON. The capture logic produced malformed output." >&2
    exit 1
fi
 
echo ""
echo "Packages: ${package_count}   Listening: ${listening_count}   SUID/SGID: ${suid_sgid_count}   World-writable: ${world_writable_count}"
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
exit 0

