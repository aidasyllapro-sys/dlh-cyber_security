#!/bin/bash
#
# script name : 8-unattended_config.sh
# purpose     : configure unattended-upgrades for MedDefense - install it
#               if missing, write /etc/apt/apt.conf.d/50unattended-upgrades
#               (security-only origin, package blacklist for kernel/
#               apache2/mysql-server/php, automatic reboot suppressed) and
#               /etc/apt/apt.conf.d/20auto-upgrades (daily timer enabled),
#               enable and start the apt-daily timers, run a dry-run to
#               confirm blacklisted packages are correctly skipped, and
#               emit a structured unattended_config.json. Idempotent: every
#               config file is regenerated fresh from the same fixed
#               content on every run, so re-running never duplicates
#               entries.
# author      : Aïda Sylla
# date        : 2026-08-11
 
set -uo pipefail
# NOTE: deliberately not using -e. A dry-run that finds packages to skip,
# or an install step that reports "already installed", are expected,
# meaningful outcomes to record - not script bugs. Every command whose
# non-zero exit is normal control flow is handled explicitly.
 
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root (it installs packages, writes to /etc/apt/apt.conf.d, and manages systemd timers). Try: sudo $0" >&2
    exit 1
fi
 
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found. This script requires jq to write the report. Install it (e.g. apt install jq) and re-run." >&2
    exit 1
fi
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_PATH="${SCRIPT_DIR}/unattended_config.json"
UU_CONF_PATH="/etc/apt/apt.conf.d/50unattended-upgrades"
AUTO_CONF_PATH="/etc/apt/apt.conf.d/20auto-upgrades"
APT_CALL_TIMEOUT=600
 
BLACKLIST=(
    "linux-image*"
    "linux-headers*"
    "mysql-server*"
    "apache2*"
    "libapache2-mod-php*"
)
 
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '%s' "${s}"
}
 
# ---------------------------------------------------------------------------
# 1. Install unattended-upgrades if missing
# ---------------------------------------------------------------------------
if dpkg -s unattended-upgrades >/dev/null 2>&1; then
    echo "[*] unattended-upgrades: already installed"
    installed_now="false"
else
    echo -n "[*] unattended-upgrades: not installed, installing...  "
    install_output_file="$(mktemp)"
    timeout "${APT_CALL_TIMEOUT}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
        apt-get install -y unattended-upgrades \
        -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
        < /dev/null > "${install_output_file}" 2>&1
    install_status=$?
    rm -f "${install_output_file}"
    if [[ "${install_status}" -eq 0 ]]; then
        echo "OK"
        installed_now="true"
    else
        echo "FAILED"
        echo "Could not install unattended-upgrades (exit ${install_status}). Cannot continue." >&2
        exit 1
    fi
fi
 
# ---------------------------------------------------------------------------
# 2. Write 50unattended-upgrades (idempotent: fixed content, atomic write
#    via temp file + mv, so re-running produces byte-identical output
#    rather than appending or duplicating entries).
# ---------------------------------------------------------------------------
echo -n "[*] Writing ${UU_CONF_PATH}...   "
 
BLACKLIST_LINES=""
for pkg in "${BLACKLIST[@]}"; do
    BLACKLIST_LINES+="    \"${pkg}\";"$'\n'
done
 
uu_tmp="$(mktemp)"
cat > "${uu_tmp}" << EOF
// Managed by 8-unattended_config.sh (MedDefense Health Systems) - do not
// hand-edit; changes will be overwritten on the next run.
 
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
 
Unattended-Upgrade::Package-Blacklist {
${BLACKLIST_LINES}};
 
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
Unattended-Upgrade::Mail "";
EOF
 
if mv "${uu_tmp}" "${UU_CONF_PATH}"; then
    chmod 644 "${UU_CONF_PATH}"
    echo "OK"
else
    echo "FAILED"
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 3. Write 20auto-upgrades (idempotent, same rewrite-fresh approach)
# ---------------------------------------------------------------------------
echo -n "[*] Writing ${AUTO_CONF_PATH}...         "
 
auto_tmp="$(mktemp)"
cat > "${auto_tmp}" << 'EOF'
// Managed by 8-unattended_config.sh (MedDefense Health Systems) - do not
// hand-edit; changes will be overwritten on the next run.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
 
if mv "${auto_tmp}" "${AUTO_CONF_PATH}"; then
    chmod 644 "${AUTO_CONF_PATH}"
    echo "OK"
else
    echo "FAILED"
    exit 1
fi
 
# ---------------------------------------------------------------------------
# 4. Enable and start the apt-daily timers
# ---------------------------------------------------------------------------
echo -n "[*] Enabling timers...                                     "
 
timer_ok=true
for timer in apt-daily.timer apt-daily-upgrade.timer; do
    if ! systemctl enable --now "${timer}" >/dev/null 2>&1; then
        timer_ok=false
    fi
done
 
if [[ "${timer_ok}" == true ]]; then
    echo "OK"
else
    echo "FAILED"
fi
 
apt_daily_state="$(systemctl show -p ActiveState --value apt-daily.timer 2>/dev/null || echo unknown)"
apt_daily_upgrade_state="$(systemctl show -p ActiveState --value apt-daily-upgrade.timer 2>/dev/null || echo unknown)"
 
# ---------------------------------------------------------------------------
# 5. Dry run, parsed for blacklist/hold/upgrade counts.
#    NOTE: the exact text of `unattended-upgrades --dry-run --debug` output
#    has varied across versions and is not something I could verify
#    against a real run while writing this script - the patterns below are
#    a reasonable best effort based on documented/typical phrasing
#    ("blacklisted", "held", "Packages that will be upgraded"), not a
#    guarantee of exact match. Verify the parsed counts against the raw
#    output on billing-srv-01 before trusting them blindly.
# ---------------------------------------------------------------------------
echo "[*] Dry run..."
 
dry_run_output="$(timeout "${APT_CALL_TIMEOUT}" unattended-upgrades --dry-run --debug 2>&1 || true)"
 
mapfile -t WOULD_UPGRADE_PKGS < <(grep -oP 'Packages that (will|would) be upgraded:\s*\K.*' <<< "${dry_run_output}" | tr ' ' '\n' | grep -v '^$')
mapfile -t BLACKLISTED_PKGS < <(grep -iP "not upgrad\w+.*blacklist|blacklisted" <<< "${dry_run_output}" | grep -oP "^\s*(pkg\s+)?'?\K[A-Za-z0-9.+-]+(?=')" | sort -u)
mapfile -t HELD_PKGS < <(grep -iP "not upgrad\w+.*held|package is on hold" <<< "${dry_run_output}" | grep -oP "^\s*(pkg\s+)?'?\K[A-Za-z0-9.+-]+(?=')" | sort -u)
 
would_upgrade_count="${#WOULD_UPGRADE_PKGS[@]}"
skipped_blacklisted_count="${#BLACKLISTED_PKGS[@]}"
skipped_held_count="${#HELD_PKGS[@]}"
 
blacklisted_display="$(IFS=,; echo "${BLACKLISTED_PKGS[*]:-}" | sed 's/,/, /g')"
echo "would upgrade:       ${would_upgrade_count}"
if [[ "${skipped_blacklisted_count}" -gt 0 ]]; then
    echo "skipped (blacklist): ${skipped_blacklisted_count} (${blacklisted_display})"
else
    echo "skipped (blacklist): 0"
fi
echo "skipped (held):      ${skipped_held_count}"
 
# ---------------------------------------------------------------------------
# 6. Write unattended_config.json
# ---------------------------------------------------------------------------
BLACKLIST_JSON="[$(for p in "${BLACKLIST[@]}"; do printf '"%s",' "$(json_escape "${p}")"; done | sed 's/,$//')]"
WOULD_UPGRADE_JSON="[$(for p in "${WOULD_UPGRADE_PKGS[@]}"; do [[ -n "${p}" ]] && printf '"%s",' "$(json_escape "${p}")"; done | sed 's/,$//')]"
BLACKLISTED_JSON="[$(for p in "${BLACKLISTED_PKGS[@]}"; do [[ -n "${p}" ]] && printf '"%s",' "$(json_escape "${p}")"; done | sed 's/,$//')]"
HELD_JSON="[$(for p in "${HELD_PKGS[@]}"; do [[ -n "${p}" ]] && printf '"%s",' "$(json_escape "${p}")"; done | sed 's/,$//')]"
 
jq -n \
    --arg conf1 "${UU_CONF_PATH}" \
    --arg conf2 "${AUTO_CONF_PATH}" \
    --argjson blacklist "${BLACKLIST_JSON}" \
    --arg t1_state "${apt_daily_state}" \
    --arg t2_state "${apt_daily_upgrade_state}" \
    --argjson would_upgrade "${would_upgrade_count}" \
    --argjson skipped_blacklisted "${skipped_blacklisted_count}" \
    --argjson skipped_held "${skipped_held_count}" \
    --argjson would_upgrade_pkgs "${WOULD_UPGRADE_JSON}" \
    --argjson blacklisted_pkgs "${BLACKLISTED_JSON}" \
    --argjson held_pkgs "${HELD_JSON}" \
    '{
        installed: true,
        config_paths: [$conf1, $conf2],
        blacklist: $blacklist,
        timer_state: { "apt-daily.timer": $t1_state, "apt-daily-upgrade.timer": $t2_state },
        dry_run_summary: {
            would_upgrade: $would_upgrade,
            skipped_blacklisted: $skipped_blacklisted,
            skipped_held: $skipped_held,
            would_upgrade_packages: $would_upgrade_pkgs,
            blacklisted_packages: $blacklisted_pkgs,
            held_packages: $held_pkgs
        }
    }' > "${OUTPUT_PATH}"
 
echo "Report saved to: $(basename "${OUTPUT_PATH}")"
exit 0
