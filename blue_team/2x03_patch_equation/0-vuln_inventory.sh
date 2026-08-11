#!/bin/bash
#
# script name : 0-vuln_inventory.sh
# purpose     : enumerate every installed package on this endpoint, cross-
#               reference against apt list --upgradable to find available
#               security updates, identify the source pocket of each
#               upgrade via apt-cache policy, extract CVE identifiers from
#               apt-get changelog (falling back to the local USN mapping
#               under /usr/share/ubuntu-advantage-tools when the changelog
#               server is unreachable), score each CVE against the
#               cve_feed.json companion feed, and emit a structured
#               vulnerability_inventory.json - the measurement step every
#               later task in this project depends on.
# author      : <your name>
# date        : 2026-08-11
 
set -euo pipefail
# Every external lookup below (apt-get changelog over the network, a CVE
# missing from cve_feed.json, apt-cache policy on a package with no
# security pocket) is EXPECTED to legitimately come back empty as part of
# normal operation - per the task's own instructions, this script must not
# fail just because a CVE is missing from the feed or the changelog server
# is unreachable. Every such lookup is explicitly guarded with "|| true" or
# an if/case check rather than left to propagate under -e.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "Warning: not running as root. apt-cache policy and apt-get changelog may return incomplete results without full repository access. Try: sudo $0" >&2
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to read cve_feed.json and write the inventory. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CVE_FEED="${SCRIPT_DIR}/cve_feed.json"
OUTPUT_PATH="${SCRIPT_DIR}/vulnerability_inventory.json"
USN_FALLBACK_DIR="/usr/share/ubuntu-advantage-tools"
CHANGELOG_TIMEOUT=8
 
if [[ -f "${CVE_FEED}" ]]; then
    if ! jq empty "${CVE_FEED}" >/dev/null 2>&1; then
        echo "cve_feed.json exists but is not valid JSON: ${CVE_FEED}" >&2
        exit 1
    fi
    HAVE_FEED=true
else
    echo "Warning: ${CVE_FEED} not found. CVSS scoring and CISA KEV flags will be unavailable for every package (per the task's own note, this must not stop the script)." >&2
    HAVE_FEED=false
fi
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}
 
echo "[*] Enumerating installed packages..."
 
# ---------------------------------------------------------------------------
# 1. Installed packages (name -> version), "install ok installed" only.
# ---------------------------------------------------------------------------
declare -A INSTALLED_VERSION
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    pkg="$(awk '{print $1}' <<< "${line}")"
    ver="$(awk '{print $2}' <<< "${line}")"
    status="$(cut -d' ' -f3- <<< "${line}")"
    if [[ "${status}" == "install ok installed" ]]; then
        INSTALLED_VERSION["${pkg}"]="${ver}"
    fi
done < <(dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' 2>/dev/null)
 
echo "    ${#INSTALLED_VERSION[@]} installed packages found."
 
# ---------------------------------------------------------------------------
# 2. Upgradable packages (name -> candidate version)
#    apt list --upgradable line format:
#    <pkg>/<suite[,now]> <candidate-version> <arch> [upgradable from: <old>]
# ---------------------------------------------------------------------------
echo "[*] Cross-referencing against apt list --upgradable..."
 
declare -A CANDIDATE_VERSION
UPGRADABLE_PKGS=()
while IFS= read -r line; do
    [[ "${line}" == Listing* ]] && continue
    [[ -z "${line}" ]] && continue
    if [[ "${line}" =~ ^([^/[:space:]]+)/[^[:space:]]+[[:space:]]+([^[:space:]]+)[[:space:]] ]]; then
        pkg="${BASH_REMATCH[1]}"
        cand="${BASH_REMATCH[2]}"
        CANDIDATE_VERSION["${pkg}"]="${cand}"
        UPGRADABLE_PKGS+=("${pkg}")
    fi
done < <(apt list --upgradable 2>/dev/null || true)
 
echo "    ${#UPGRADABLE_PKGS[@]} upgradable packages found."
 
# ---------------------------------------------------------------------------
# 3. Source pocket per upgradable package, via apt-cache policy.
#    Looks for the version-table line matching the candidate version, then
#    the following indented line naming the archive suite (e.g.
#    "jammy-security/main"), and derives a short pocket label from it.
# ---------------------------------------------------------------------------
get_source_pocket() {
    local pkg="$1" candidate="$2" policy suite_paths suite security_suite first_suite
    policy="$(apt-cache policy "${pkg}" 2>/dev/null || true)"
    [[ -z "${policy}" ]] && { echo "unknown"; return; }
 
    # A candidate version can be listed under MORE THAN ONE source line at
    # once (e.g. simultaneously in jammy-updates and jammy-security, same
    # version) - scan every source line belonging to the candidate's block
    # (stops at the next version-table entry, i.e. a line starting with a
    # version token followed by a priority number) rather than just the
    # first one, and prefer a *-security suite if any of them is one.
    suite_paths="$(awk -v cand="${candidate}" '
        $1 == cand { found=1; next }
        found && /^[[:space:]]*(\*\*\*[[:space:]]+)?[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]*$/ { found=0 }
        found && /http/ {
            for (i=1;i<=NF;i++) {
                if ($i !~ /^https?:/ && $i ~ /\//) { print $i }
            }
        }
    ' <<< "${policy}")"
 
    if [[ -z "${suite_paths}" ]]; then
        echo "unknown"
        return
    fi
 
    security_suite=""
    first_suite=""
    while IFS= read -r suite_path; do
        suite="${suite_path%%/*}"
        [[ -z "${first_suite}" ]] && first_suite="${suite}"
        if [[ "${suite}" == *-security ]]; then
            security_suite="${suite}"
            break
        fi
    done <<< "${suite_paths}"
 
    if [[ -n "${security_suite}" ]]; then
        echo "${security_suite}"
    else
        echo "${first_suite}"
    fi
}
 
# ---------------------------------------------------------------------------
# 4. CVE extraction: apt-get changelog first (network), USN fallback second.
#    NOTE on the USN fallback: I have not been able to inspect a real
#    /usr/share/ubuntu-advantage-tools installation to confirm its exact
#    internal file layout for a USN-to-CVE mapping, so this fallback is a
#    best-effort search (grep the package name across that directory) -
#    verify its actual structure on the real endpoint before trusting this
#    path blindly; the apt-get changelog path is the well-documented one.
# ---------------------------------------------------------------------------
extract_cves_from_changelog() {
    local pkg="$1" changelog
    changelog="$(timeout "${CHANGELOG_TIMEOUT}" apt-get changelog "${pkg}" -- 2>/dev/null || true)"
    [[ -z "${changelog}" ]] && return 1
    grep -oE 'CVE-[0-9]{4}-[0-9]{4,7}' <<< "${changelog}" | sort -u
    return 0
}
 
extract_cves_from_usn_fallback() {
    local pkg="$1"
    [[ -d "${USN_FALLBACK_DIR}" ]] || return 1
    grep -rl "${pkg}" "${USN_FALLBACK_DIR}" 2>/dev/null | xargs -r grep -ohE 'CVE-[0-9]{4}-[0-9]{4,7}' 2>/dev/null | sort -u
}
 
# ---------------------------------------------------------------------------
# 5 & 6. CVSS / KEV lookup and severity classification.
#    Expected cve_feed.json schema (a snapshot feed for this exercise):
#      { "CVE-2024-1086": { "cvss": 7.8, "in_kev": true }, ... }
#    A CVE absent from the feed is treated as unscored (cvss null,
#    in_kev false), per the task's explicit "must not fail" requirement.
# ---------------------------------------------------------------------------
lookup_cvss() {
    local cve="$1"
    [[ "${HAVE_FEED}" == true ]] || { echo "null"; return; }
    jq -r --arg c "${cve}" '.[$c].cvss // "null"' "${CVE_FEED}" 2>/dev/null || echo "null"
}
lookup_kev() {
    local cve="$1"
    [[ "${HAVE_FEED}" == true ]] || { echo "false"; return; }
    jq -r --arg c "${cve}" '.[$c].in_kev // false' "${CVE_FEED}" 2>/dev/null || echo "false"
}
 
classify_severity() {
    local score="$1"
    if [[ "${score}" == "null" || -z "${score}" ]]; then
        echo "unknown"; return
    fi
    awk -v s="${score}" 'BEGIN {
        if (s >= 9.0) print "critical";
        else if (s >= 7.0) print "high";
        else if (s >= 4.0) print "medium";
        else if (s >= 0.1) print "low";
        else print "none";
    }'
}
 
# ---------------------------------------------------------------------------
# Build the inventory (security-pocket upgrades only - these are the
# upgrades actually tied to a CVE; updates/backports pockets are routine
# bugfix/feature churn and are not vulnerability data by themselves).
# ---------------------------------------------------------------------------
echo "[*] Extracting CVEs and scoring severity for security-pocket upgrades..."
 
ENTRIES=()
security_pkg_count=0
 
for pkg in "${UPGRADABLE_PKGS[@]}"; do
    candidate="${CANDIDATE_VERSION[${pkg}]}"
    installed="${INSTALLED_VERSION[${pkg}]:-unknown}"
    pocket="$(get_source_pocket "${pkg}" "${candidate}")"
 
    if [[ "${pocket}" != *-security ]]; then
        continue
    fi
    security_pkg_count=$((security_pkg_count + 1))
 
    cve_output=""
    if cve_output="$(extract_cves_from_changelog "${pkg}")"; then
        mapfile -t cves <<< "${cve_output}"
    else
        mapfile -t cves < <(extract_cves_from_usn_fallback "${pkg}")
    fi
 
    max_cvss="null"
    in_kev="false"
    cves_json_parts=()
    for cve in "${cves[@]}"; do
        [[ -z "${cve}" ]] && continue
        cves_json_parts+=("\"$(json_escape "${cve}")\"")
        score="$(lookup_cvss "${cve}")"
        kev="$(lookup_kev "${cve}")"
        [[ "${kev}" == "true" ]] && in_kev="true"
        if [[ "${score}" != "null" ]]; then
            if [[ "${max_cvss}" == "null" ]] || awk -v a="${score}" -v b="${max_cvss}" 'BEGIN{exit !(a>b)}'; then
                max_cvss="${score}"
            fi
        fi
    done
 
    severity="$(classify_severity "${max_cvss}")"
    cves_json="[$(IFS=,; echo "${cves_json_parts[*]:-}")]"
 
    entry=$(printf '{"package":"%s","installed_version":"%s","candidate_version":"%s","source_pocket":"%s","cves":%s,"max_cvss":%s,"severity":"%s","in_cisa_kev":%s}' \
        "$(json_escape "${pkg}")" "$(json_escape "${installed}")" "$(json_escape "${candidate}")" \
        "$(json_escape "${pocket}")" "${cves_json}" "${max_cvss}" "${severity}" "${in_kev}")
 
    ENTRIES+=("${entry}")
done
 
echo "    ${security_pkg_count} security-pocket packages processed, ${#ENTRIES[@]} vulnerability entries recorded."
 
# ---------------------------------------------------------------------------
# Write the inventory
# ---------------------------------------------------------------------------
{
    printf '{'
    printf '"generated":"%s",' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '"hostname":"%s",' "$(json_escape "$(hostname)")"
    printf '"installed_package_count":%s,' "${#INSTALLED_VERSION[@]}"
    printf '"upgradable_package_count":%s,' "${#UPGRADABLE_PKGS[@]}"
    printf '"cve_feed_available":%s,' "${HAVE_FEED}"
    printf '"packages":['
    for idx in "${!ENTRIES[@]}"; do
        [[ "${idx}" -gt 0 ]] && printf ','
        printf '%s' "${ENTRIES[$idx]}"
    done
    printf ']'
    printf '}'
} | jq '.' > "${OUTPUT_PATH}"
 
echo "Vulnerability inventory saved to: ${OUTPUT_PATH}"
