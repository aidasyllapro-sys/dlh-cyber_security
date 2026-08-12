#!/bin/bash
#
# script name : 6-config_drift.sh
# purpose     : compare the conffile_hashes captured in pre_patch_state.json
#               (Task 2) against the current SHA-256 of every tracked
#               config file under /etc, classify each as unchanged /
#               modified / missing / new, capture a truncated unified diff
#               for modified files when dpkg has preserved the new
#               maintainer version alongside the local one
#               (.dpkg-dist/.dpkg-new), and cross-reference every
#               modification against patch_execution_log.json (Task 4) to
#               mark it expected (the owning package was actually upgraded
#               this run) or unexpected (drifted without a matching
#               upgrade - the case this detector exists to catch). Emits
#               config_drift.json.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -uo pipefail
# NOTE: deliberately not using -e. Detecting drift, a missing file, or an
# unowned conffile are all expected, meaningful outcomes for this script to
# report - not bugs. Every command whose non-zero exit is normal control
# flow is handled explicitly.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "Warning: not running as root. Reading some /etc files or resolving dpkg ownership may be incomplete without full privileges. Try: sudo $0" >&2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to read the input files and write the report. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRE_STATE_PATH="${SCRIPT_DIR}/pre_patch_state.json"
EXEC_LOG_PATH="${SCRIPT_DIR}/patch_execution_log.json"
OUTPUT_PATH="${SCRIPT_DIR}/config_drift.json"
DIFF_MAX_LINES=40
 
if [[ ! -f "${PRE_STATE_PATH}" ]]; then
    echo "pre_patch_state.json not found at ${PRE_STATE_PATH}. Run 2-pre_patch_snapshot.sh before patching, next time." >&2
    exit 1
fi
if ! jq empty "${PRE_STATE_PATH}" >/dev/null 2>&1; then
    echo "pre_patch_state.json is not valid JSON: ${PRE_STATE_PATH}" >&2
    exit 1
fi
 
HAVE_EXEC_LOG=false
if [[ -f "${EXEC_LOG_PATH}" ]] && jq empty "${EXEC_LOG_PATH}" >/dev/null 2>&1; then
    HAVE_EXEC_LOG=true
else
    echo "Warning: patch_execution_log.json not found or invalid - every modification will be classified 'unexpected' since no upgrade record can be cross-referenced." >&2
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
# Same usrmerge-aware dpkg -S resolution lesson learned the hard way on
# billing-srv-01 in Task 1: try the raw path first, then the canonical
# (readlink -f) path, since this system's dpkg database is inconsistently
# keyed between the two depending on the package.
resolve_owning_package() {
    local raw_path="$1" canonical result pkg
    result="$(dpkg -S "${raw_path}" 2>/dev/null || true)"
    if [[ -z "${result}" ]]; then
        canonical="$(readlink -f "${raw_path}" 2>/dev/null || true)"
        if [[ -n "${canonical}" && "${canonical}" != "${raw_path}" ]]; then
            result="$(dpkg -S "${canonical}" 2>/dev/null || true)"
        fi
    fi
    [[ -z "${result}" ]] && { echo ""; return; }
    cut -d: -f1 <<< "${result}" | head -1
}
 
# Was this package's upgrade actually attempted and succeeded in the most
# recent patch execution log?
package_was_upgraded() {
    local pkg="$1"
    [[ "${HAVE_EXEC_LOG}" != true || -z "${pkg}" ]] && { echo "false"; return; }
    jq -r --arg p "${pkg}" '
        [.entries[]? | select(.package == $p and .status == "succeeded")] | length > 0
    ' "${EXEC_LOG_PATH}" 2>/dev/null || echo "false"
}
 
echo "[*] Detecting configuration drift since the pre-patch snapshot..."
 
# ---------------------------------------------------------------------------
# Current full conffile list, same method as 2-pre_patch_snapshot.sh, used
# to detect "new" tracked conffiles that did not exist at snapshot time.
# ---------------------------------------------------------------------------
mapfile -t CURRENT_CONFFILE_PATHS < <(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | grep -oE '^ /etc/\S+' | sed 's/^ //' | sort -u)
 
mapfile -t PRE_ENTRIES < <(jq -c '.conffile_hashes[]?' "${PRE_STATE_PATH}")
 
declare -A PRE_PATH_SEEN
FILES=()
unchanged_count=0
modified_count=0
missing_count=0
new_count=0
unexpected_count=0
 
for entry in "${PRE_ENTRIES[@]}"; do
    [[ -z "${entry}" ]] && continue
    path="$(jq -r '.path' <<< "${entry}")"
    pre_hash="$(jq -r '.sha256' <<< "${entry}")"
    PRE_PATH_SEEN["${path}"]=1
 
    if [[ ! -f "${path}" ]]; then
        classification="missing"
        missing_count=$((missing_count + 1))
        owning_pkg="$(resolve_owning_package "${path}")"
        expected="false"
        entry_json=$(jq -n --arg path "${path}" --arg cls "${classification}" --arg pkg "${owning_pkg}" \
            '{path: $path, classification: $cls, owning_package: $pkg, pre_sha256: null, current_sha256: null, expected: false, diff: null}')
        FILES+=("${entry_json}")
        continue
    fi
 
    current_hash="$(sha256sum "${path}" 2>/dev/null | awk '{print $1}' || true)"
 
    if [[ "${pre_hash}" == "null" || -z "${pre_hash}" ]]; then
        # Pre-patch hash could not be computed at snapshot time (file was
        # unreadable/missing then) - treat as unchanged if it still can't
        # be meaningfully compared, rather than falsely flagging drift.
        classification="unchanged"
        unchanged_count=$((unchanged_count + 1))
        FILES+=("$(jq -n --arg path "${path}" --arg cls "${classification}" \
            '{path: $path, classification: $cls, owning_package: null, pre_sha256: null, current_sha256: null, expected: true, diff: null}')")
        continue
    fi
 
    if [[ "${current_hash}" == "${pre_hash}" ]]; then
        classification="unchanged"
        unchanged_count=$((unchanged_count + 1))
        FILES+=("$(jq -n --arg path "${path}" --arg cls "${classification}" --arg h "${current_hash}" \
            '{path: $path, classification: $cls, owning_package: null, pre_sha256: $h, current_sha256: $h, expected: true, diff: null}')")
        continue
    fi
 
    # --- modified ---
    classification="modified"
    modified_count=$((modified_count + 1))
    owning_pkg="$(resolve_owning_package "${path}")"
    was_upgraded="$(package_was_upgraded "${owning_pkg}")"
 
    if [[ "${was_upgraded}" == "true" ]]; then
        expected="true"
    else
        expected="false"
        unexpected_count=$((unexpected_count + 1))
    fi
 
    # dpkg preserves the new maintainer version alongside the kept local
    # file as <path>.dpkg-dist (when --force-confold kept the local copy)
    # or <path>.dpkg-new - diff against whichever exists. Without the
    # original pre-patch file content saved (Task 2 only recorded hashes),
    # a real diff is only possible when one of these dpkg-preserved
    # siblings is present; otherwise the hash mismatch alone is reported,
    # honestly, rather than fabricating a diff with no real content to
    # compare against.
    diff_text="null"
    for candidate in "${path}.dpkg-dist" "${path}.dpkg-new"; do
        if [[ -f "${candidate}" ]]; then
            diff_output="$(diff -u "${path}" "${candidate}" 2>/dev/null | head -n "${DIFF_MAX_LINES}" || true)"
            if [[ -n "${diff_output}" ]]; then
                diff_text="$(jq -Rs '.' <<< "${diff_output}")"
            fi
            break
        fi
    done
 
    entry_json=$(jq -n --arg path "${path}" --arg cls "${classification}" --arg pkg "${owning_pkg}" \
        --arg pre_h "${pre_hash}" --arg cur_h "${current_hash}" --argjson exp "${was_upgraded}" \
        --argjson diff "${diff_text}" \
        '{path: $path, classification: $cls, owning_package: $pkg, pre_sha256: $pre_h, current_sha256: $cur_h, expected: $exp, diff: $diff}')
    FILES+=("${entry_json}")
done
 
# ---------------------------------------------------------------------------
# New tracked conffiles: present now, not present in the pre-patch snapshot
# at all (added by a package installed/upgraded during the patch run).
# ---------------------------------------------------------------------------
for path in "${CURRENT_CONFFILE_PATHS[@]}"; do
    [[ -z "${path}" ]] && continue
    [[ -n "${PRE_PATH_SEEN[${path}]:-}" ]] && continue
    new_count=$((new_count + 1))
    owning_pkg="$(resolve_owning_package "${path}")"
    current_hash="$(sha256sum "${path}" 2>/dev/null | awk '{print $1}' || true)"
    FILES+=("$(jq -n --arg path "${path}" --arg pkg "${owning_pkg}" --arg h "${current_hash}" \
        '{path: $path, classification: "new", owning_package: $pkg, pre_sha256: null, current_sha256: $h, expected: true, diff: null}')")
done
 
total_files=$((unchanged_count + modified_count + missing_count + new_count))
 
echo "Unchanged: ${unchanged_count}  Modified: ${modified_count}  Missing: ${missing_count}  New: ${new_count}"
if [[ "${unexpected_count}" -eq 0 ]]; then
    echo "VERDICT: PASS - no unexpected drift"
else
    echo "VERDICT: FAIL - ${unexpected_count} unexpected drift file(s) detected"
fi
 
FILES_JSON="[$(IFS=,; echo "${FILES[*]:-}")]"
 
# NOTE: found the hard way on billing-srv-01 - with ~1000 tracked
# conffiles, the assembled files array is too large to pass as a single
# --argjson command-line argument (jq: "Argument list too long", an OS
# ARG_MAX limit, not a jq bug). Writing it to a temp file and reading it
# with --slurpfile avoids the command-line length limit entirely.
FILES_TMP_FILE="$(mktemp)"
printf '%s' "${FILES_JSON}" > "${FILES_TMP_FILE}"
 
jq -n \
    --arg generated "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --argjson total "${total_files}" \
    --argjson unchanged "${unchanged_count}" \
    --argjson modified "${modified_count}" \
    --argjson missing "${missing_count}" \
    --argjson new "${new_count}" \
    --argjson unexpected "${unexpected_count}" \
    --slurpfile files_wrap "${FILES_TMP_FILE}" \
    '{
        generated_at: $generated,
        summary: { total: $total, unchanged: $unchanged, modified: $modified, missing: $missing, new: $new, unexpected: $unexpected },
        files: $files_wrap[0]
    }' > "${OUTPUT_PATH}"
 
rm -f "${FILES_TMP_FILE}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
 
if [[ "${unexpected_count}" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
