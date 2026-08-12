#!/bin/bash
#
# script name : 2-pre_patch_snapshot.sh
# purpose     : capture the full pre-patch state of this endpoint - every
#               installed package and its version, the ActiveState/
#               SubState/MainPID of every active systemd service, every
#               listening socket, the SHA-256 hash of every package-tracked
#               configuration file under /etc, the running kernel release,
#               and whether a reboot is already pending - into a single,
#               stable-schema pre_patch_state.json. This is the baseline
#               every later validation and rollback task in this project
#               compares against.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -euo pipefail
# Every per-item lookup below (a service with no MainPID, a conffile that
# no longer exists on disk, ss producing no output on a host with nothing
# listening) is expected to legitimately come back empty for some entries
# as part of normal operation, and must not abort the whole snapshot.
# Every such lookup is guarded with an explicit if/case or "|| true"
# rather than left to propagate under -e.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "Warning: not running as root. ss -tulnp and systemctl show may return incomplete results (process names/PIDs hidden) without full privileges. Try: sudo $0" >&2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to assemble pre_patch_state.json. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${SCRIPT_DIR}/pre_patch_state.json"
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
echo "[*] Capturing pre-patch state..."
 
# ---------------------------------------------------------------------------
# 1. Package versions (every installed package, via dpkg-query)
# ---------------------------------------------------------------------------
PACKAGES_JSON_PARTS=()
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    pkg="$(awk '{print $1}' <<< "${line}")"
    ver="$(awk '{print $2}' <<< "${line}")"
    status="$(cut -d' ' -f3- <<< "${line}")"
    [[ "${status}" != "install ok installed" ]] && continue
    PACKAGES_JSON_PARTS+=("$(printf '{"package":"%s","version":"%s"}' "$(json_escape "${pkg}")" "$(json_escape "${ver}")")")
done < <(dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' 2>/dev/null)
PACKAGES_JSON="[$(IFS=,; echo "${PACKAGES_JSON_PARTS[*]:-}")]"
package_count="${#PACKAGES_JSON_PARTS[@]}"
echo "    ${package_count} packages recorded."
 
# ---------------------------------------------------------------------------
# 2. Service state for every active systemd service
# ---------------------------------------------------------------------------
SERVICES_JSON_PARTS=()
service_count=0
if command -v systemctl >/dev/null 2>&1; then
    mapfile -t ACTIVE_SERVICES < <(systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}')
    for unit in "${ACTIVE_SERVICES[@]}"; do
        [[ -z "${unit}" ]] && continue
        # NOTE: `systemctl show -p A -p B -p C --value` does NOT guarantee
        # its output lines follow the order the -p flags were given on the
        # command line - systemd uses its own internal property ordering
        # (confirmed on billing-srv-01: MainPID/ActiveState/SubState came
        # back in that order despite being requested as ActiveState/
        # SubState/MainPID). Relying on line position silently misaligned
        # every field. Dropping --value and grepping each KEY=value line
        # explicitly by its property name is order-independent and safe.
        show_out="$(systemctl show -p ActiveState -p SubState -p MainPID "${unit}" 2>/dev/null || true)"
        [[ -z "${show_out}" ]] && continue
        active_state="$(grep -oP '^ActiveState=\K.*' <<< "${show_out}" || true)"
        sub_state="$(grep -oP '^SubState=\K.*' <<< "${show_out}" || true)"
        main_pid="$(grep -oP '^MainPID=\K.*' <<< "${show_out}" || true)"
        [[ -z "${main_pid}" ]] && main_pid="0"
        SERVICES_JSON_PARTS+=("$(printf '{"service":"%s","active_state":"%s","sub_state":"%s","main_pid":%s}' \
            "$(json_escape "${unit}")" "$(json_escape "${active_state}")" "$(json_escape "${sub_state}")" "${main_pid}")")
        service_count=$((service_count + 1))
    done
else
    echo "Warning: systemctl not found - services will be empty in the snapshot." >&2
fi
SERVICES_JSON="[$(IFS=,; echo "${SERVICES_JSON_PARTS[*]:-}")]"
echo "    ${service_count} active services recorded."
 
# ---------------------------------------------------------------------------
# 3. Listening sockets via ss -tulnp
#    Typical line: "tcp   LISTEN 0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=123,fd=3))"
# ---------------------------------------------------------------------------
LISTENING_JSON_PARTS=()
listening_count=0
while IFS= read -r line; do
    [[ "${line}" == Netid* ]] && continue
    [[ -z "${line}" ]] && continue
    proto="$(awk '{print $1}' <<< "${line}")"
    local_addr="$(awk '{print $5}' <<< "${line}")"
    proc_info="$(grep -oP 'users:\(\(\K[^)]*' <<< "${line}" || true)"
    proc_name="$(grep -oP '^"?\K[^",]*' <<< "${proc_info}" || true)"
    # A listening socket can be shared by more than one process (e.g. a
    # socket-activated or forked service) - users:(("a",pid=1,..),("b",
    # pid=2,..)). Only the first PID is kept: without "head -1", command
    # substitution would join multiple matches with spaces (e.g. "1 2"),
    # producing an invalid JSON numeric literal downstream.
    pid="$(grep -oP 'pid=\K[0-9]+' <<< "${proc_info}" | head -1 || true)"
    [[ -z "${pid}" ]] && pid="0"
    LISTENING_JSON_PARTS+=("$(printf '{"protocol":"%s","local_address":"%s","process":"%s","pid":%s}' \
        "$(json_escape "${proto}")" "$(json_escape "${local_addr}")" "$(json_escape "${proc_name}")" "${pid}")")
    listening_count=$((listening_count + 1))
done < <(ss -tulnp 2>/dev/null || true)
LISTENING_JSON="[$(IFS=,; echo "${LISTENING_JSON_PARTS[*]:-}")]"
echo "    ${listening_count} listening sockets recorded."
 
# ---------------------------------------------------------------------------
# 4. SHA-256 hashes of every package-tracked conffile under /etc
#    dpkg-query's ${Conffiles} field lists every conffile dpkg tracks
#    (path + dpkg's own recorded MD5) across ALL packages when no package
#    name is given. Only the path is used here; the hash is recomputed
#    live via sha256sum rather than reusing dpkg's stored MD5, since the
#    task explicitly asks for SHA-256 and dpkg's own record can be stale
#    if the file was legitimately modified by an admin since install.
# ---------------------------------------------------------------------------
CONFFILE_JSON_PARTS=()
conffile_count=0
mapfile -t CONFFILE_PATHS < <(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | grep -oE '^ /etc/\S+' | sed 's/^ //' | sort -u)
for path in "${CONFFILE_PATHS[@]}"; do
    [[ -z "${path}" ]] && continue
    if [[ -f "${path}" ]]; then
        hash="$(sha256sum "${path}" 2>/dev/null | awk '{print $1}' || true)"
    else
        hash="null_missing"
    fi
    [[ -z "${hash}" ]] && hash="null_unreadable"
    if [[ "${hash}" == "null_missing" || "${hash}" == "null_unreadable" ]]; then
        CONFFILE_JSON_PARTS+=("$(printf '{"path":"%s","sha256":null,"note":"%s"}' "$(json_escape "${path}")" "${hash#null_}")")
    else
        CONFFILE_JSON_PARTS+=("$(printf '{"path":"%s","sha256":"%s"}' "$(json_escape "${path}")" "${hash}")")
    fi
    conffile_count=$((conffile_count + 1))
done
CONFFILE_JSON="[$(IFS=,; echo "${CONFFILE_JSON_PARTS[*]:-}")]"
echo "    ${conffile_count} tracked conffiles hashed."
 
# ---------------------------------------------------------------------------
# 5. Kernel release and pending-reboot indicator
# ---------------------------------------------------------------------------
kernel_release="$(uname -r)"
reboot_required="false"
[[ -f /var/run/reboot-required ]] && reboot_required="true"
 
# ---------------------------------------------------------------------------
# Assemble and write pre_patch_state.json
#    NOTE: the raw compact JSON is saved to a .raw file BEFORE being handed
#    to jq. If jq fails to parse it, the .raw file lets you inspect the
#    exact byte at the reported column instead of losing the data - jq
#    itself never receives an unparsed string it can show you back.
# ---------------------------------------------------------------------------
RAW_PATH="${OUTPUT_PATH}.raw"
{
    printf '{'
    printf '"timestamp":"%s",' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '"hostname":"%s",' "$(json_escape "$(hostname)")"
    printf '"kernel":"%s",' "$(json_escape "${kernel_release}")"
    printf '"packages":%s,' "${PACKAGES_JSON}"
    printf '"services":%s,' "${SERVICES_JSON}"
    printf '"listening":%s,' "${LISTENING_JSON}"
    printf '"conffile_hashes":%s,' "${CONFFILE_JSON}"
    printf '"reboot_required":%s' "${reboot_required}"
    printf '}'
} > "${RAW_PATH}"
 
if jq '.' "${RAW_PATH}" > "${OUTPUT_PATH}" 2>/tmp/pre_patch_jq_error.log; then
    rm -f "${RAW_PATH}" /tmp/pre_patch_jq_error.log
else
    echo "ERROR: the assembled JSON failed to parse. Raw (unparsed) output kept at: ${RAW_PATH}" >&2
    cat /tmp/pre_patch_jq_error.log >&2
    err_col="$(grep -oP 'column \K[0-9]+' /tmp/pre_patch_jq_error.log | head -1 || true)"
    if [[ -n "${err_col}" ]]; then
        ctx_start=$(( err_col > 100 ? err_col - 100 : 1 ))
        ctx_end=$(( err_col + 100 ))
        echo "Inspect the exact failure point with:" >&2
        echo "    cut -c${ctx_start}-${ctx_end} ${RAW_PATH}" >&2
    fi
    exit 1
fi
 
snapshot_size_bytes="$(stat -c %s "${OUTPUT_PATH}" 2>/dev/null || echo 0)"
snapshot_size_human="$(awk -v b="${snapshot_size_bytes}" 'BEGIN {
    if (b >= 1048576) printf "%.1f MB", b/1048576;
    else if (b >= 1024) printf "%.0f KB", b/1024;
    else printf "%d B", b;
}')"
 
echo "Snapshot: $(basename "${OUTPUT_PATH}")"
echo "Size: ${snapshot_size_human}"
echo "Kernel: ${kernel_release}"
echo "Reboot required: ${reboot_required}"
