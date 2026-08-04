#!/bin/bash
#
# 1-cis_profile.sh
#
# Goal: generate a focused, threat-driven CIS hardening profile for
# MedDefense's three Linux servers (billing-srv-01, web-srv-01,
# log-srv-01), covering exactly 15 controls that later hardening
# scripts (2-ssh_hardening.sh onward) will consume as their input.
#
# This is NOT a generic CIS Benchmark summary. Every control below is
# tied to a specific fact already established by 0-baseline_snapshot.sh
# or a specific MedDefense finding/Crimson Tide phase. A control that
# cannot be justified against a real fact is not included.
#
# This script makes NO changes to the system. It only writes the
# control profile itself. Re-running it always regenerates the same
# 15-control profile from the same source data below (idempotent by
# design: the output is a pure function of the data in this script,
# not of anything read from the live system).
 
set -euo pipefail
 
OUTPUT_FILE="./cis_profile.json"
 
# ---------------------------------------------------------------------
# JSON ESCAPE HELPER (same pattern as 0-baseline_snapshot.sh)
# ---------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}
 
# ---------------------------------------------------------------------
# THE 15 CONTROLS
# ---------------------------------------------------------------------
# Parallel arrays, one element per control, index-aligned. This is the
# single source of truth: every summary count printed at the end is
# computed FROM this data, never hand-typed separately, so the
# printed summary can never silently drift out of sync with the
# actual controls below.
#
# Note on control_id numbering: section numbers and sub-item numbers are
# verified directly against the real CIS Ubuntu 22.04 LTS Benchmark table
# of contents (1=Initial Setup, 2=Services, 3=Network, 4=Host Based
# Firewall, 5=Access Control, 6=Logging and Auditing, 7=System
# Maintenance). Two controls in this profile (SUID/SGID review, true
# home Section 7; service minimization, true home Section 2) are
# deliberately grouped under Section 1 here for consolidated deployment
# purposes; this is disclosed explicitly in each control's own
# justification field, not a numbering error. One SSH control
# (password authentication) references section 5.1 without a verified
# exact sub-item number; see that control's justification for detail.
 
CONTROL_ID=()
TITLE=()
CIS_SECTION=()
SEVERITY=()
ASSET_SCOPE=()
THREAT_MAPPING=()
IMPLEMENTATION_TASK=()
VERIFICATION_METHOD=()
JUSTIFICATION=()
 
add_control() {
  CONTROL_ID+=("$1")
  TITLE+=("$2")
  CIS_SECTION+=("$3")
  SEVERITY+=("$4")
  ASSET_SCOPE+=("$5")
  THREAT_MAPPING+=("$6")
  IMPLEMENTATION_TASK+=("$7")
  VERIFICATION_METHOD+=("$8")
  JUSTIFICATION+=("$9")
}
 
# --- SSH (CIS Section 5.1, "Configure SSH Server", verified against real TOC) ---
add_control "5.1" \
  "Disable SSH password authentication" \
  "5" "critical" "billing-srv-01,web-srv-01,log-srv-01" \
  "1x02 Finding 009 (SSH password auth enabled); Task 0 baseline confirmed passwordauthentication=yes; Crimson Tide Phase 3 (SSH-based lateral movement)" \
  "2-ssh_hardening.sh" \
  "sshd -T | grep -i passwordauthentication returns no" \
  "Baseline confirms password auth is currently enabled on billing-srv-01; key-based authentication makes credential brute-forcing practically useless. Note: no single dedicated sub-item for this exact setting was located in the verified table of contents (5.1.1-5.1.22); section 5.1 (Configure SSH Server) is the confirmed parent section, sub-item pending verification against the full text at pages 476-533"
 
add_control "5.1.20" \
  "Disable direct SSH root login" \
  "5" "critical" "billing-srv-01,web-srv-01,log-srv-01" \
  "1x02 Finding 009; Task 0 baseline confirmed permitrootlogin=yes; Crimson Tide Phase 3 and Phase 6" \
  "2-ssh_hardening.sh" \
  "sshd -T | grep -i permitrootlogin returns no" \
  "Baseline confirms root login is currently permitted directly over SSH; forcing a named account first preserves individual accountability for every privileged action taken. Verified as CIS 5.1.20 'Ensure sshd PermitRootLogin is disabled' against the real table of contents"
 
add_control "5.1.4" \
  "Restrict SSH access to an explicit allowed-users list" \
  "5" "high" "billing-srv-01,web-srv-01,log-srv-01" \
  "Crimson Tide Phase 3 (lateral movement via any valid credential)" \
  "2-ssh_hardening.sh" \
  "sshd -T | grep -i allowusers lists only approved accounts" \
  "Baseline shows 4 real accounts (analyst, medadmin, sysadmin, mike); an explicit allow-list ensures a compromised or forgotten account cannot authenticate over SSH even if its credential is later exposed. Verified as CIS 5.1.4 'Ensure sshd access is configured' against the real table of contents"
 
# --- PAM (CIS Section 5.3, "Pluggable Authentication Modules", verified against real TOC) ---
add_control "5.3.3.2.7" \
  "Enforce password quality requirements via pam_pwquality" \
  "5" "high" "billing-srv-01,web-srv-01,log-srv-01" \
  "Weak credential hygiene enabling online cracking; Crimson Tide Phase 3" \
  "3-pam_password_quality.sh" \
  "grep pam_pwquality /etc/pam.d/common-password shows minlen and complexity requirements" \
  "No password complexity requirement is currently enforced at the PAM layer; this closes the gap before a weak password is ever created, not merely after it is guessed. Verified as CIS 5.3.3.2.7 'Ensure password quality checking is enforced' against the real table of contents"
 
add_control "5.3.3.1.1" \
  "Enable account lockout via pam_faillock after repeated failed logins" \
  "5" "high" "billing-srv-01,web-srv-01,log-srv-01" \
  "Crimson Tide Phase 3 (credential brute-forcing)" \
  "4-pam_account_lockout.sh" \
  "grep pam_faillock /etc/pam.d/common-auth is present and enabled" \
  "Without this control an attacker with network access to any authentication service can attempt unlimited passwords for free; this turns brute-forcing into a slow, detectable operation. Verified as CIS 5.3.3.1.1 'Ensure password failed attempts lockout is configured' against the real table of contents"
 
# --- Process hardening: core dumps (CIS Section 1.5, "Additional Process Hardening",
#     verified against real TOC; NOT Network as originally assumed) ---
add_control "1.5.3" \
  "Restrict core dumps (fs.suid_dumpable=0)" \
  "1" "critical" "billing-srv-01,web-srv-01,log-srv-01" \
  "1x02 Finding 026 (47 known kernel CVEs, same weakness class); Task 0 baseline confirmed fs.suid_dumpable=2" \
  "5-kernel_hardening.sh" \
  "sysctl fs.suid_dumpable returns 0" \
  "Baseline confirmed fs.suid_dumpable=2, the least restrictive possible value; a process crash could currently expose credentials or session data resident in memory to any local user. Verified as CIS 1.5.3 'Ensure suid_dumpable is configured' against the real table of contents; this control lives under Initial Setup / Process Hardening, not Network, correcting an earlier assumption"
 
# --- Network Kernel Parameters (CIS Section 3.3.1, verified against real TOC) ---
add_control "3.3.1.8" \
  "Reject ICMP redirects" \
  "3" "high" "billing-srv-01,web-srv-01,log-srv-01" \
  "On-path traffic manipulation consistent with Crimson Tide's network-level lateral movement" \
  "5-kernel_hardening.sh" \
  "sysctl net.ipv4.conf.all.accept_redirects returns 0" \
  "Baseline shows this already at 0 on billing-srv-01 but must be verified and enforced identically on web-srv-01 and log-srv-01, since one unhardened host undermines the whole segment. Verified as CIS 3.3.1.8 'Ensure net.ipv4.conf.all.accept_redirects is configured' against the real table of contents"
 
add_control "3.3.1.1" \
  "Disable IP forwarding" \
  "3" "high" "billing-srv-01,web-srv-01,log-srv-01" \
  "Prevents a compromised host being repurposed as an internal pivot, directly relevant to the flat-network lateral movement pattern in every prior kill chain analysis" \
  "5-kernel_hardening.sh" \
  "sysctl net.ipv4.ip_forward returns 0" \
  "Baseline confirmed ip_forward=1 on billing-srv-01, a database and web server with no legitimate routing function; this setting has no operational justification. Verified as CIS 3.3.1.1 'Ensure net.ipv4.ip_forward is configured' against the real table of contents"
 
add_control "3.3.1.18" \
  "Enable TCP SYN cookies" \
  "3" "medium" "billing-srv-01,web-srv-01,log-srv-01" \
  "Network-layer denial of service resilience, same kernel-hardening class as Finding 026" \
  "5-kernel_hardening.sh" \
  "sysctl net.ipv4.tcp_syncookies returns 1" \
  "Baseline already shows this enabled by Ubuntu's own default; retained as an explicitly verified control rather than an unconfirmed assumption. Verified as CIS 3.3.1.18 'Ensure net.ipv4.tcp_syncookies is configured' against the real table of contents"
 
# --- Filesystem (CIS Section 1.1, Filesystem, verified against real TOC) ---
add_control "7.1.13" \
  "Identify and remove unauthorized SUID binaries" \
  "1" "critical" "billing-srv-01" \
  "Direct baseline finding: /usr/local/bin/oldtool and /opt/legacy/setuid-app, two non-standard SUID binaries matching no known Ubuntu package" \
  "6-filesystem_hardening.sh" \
  "SUID list cross-referenced against Task 0 baseline contains zero unexplained entries" \
  "billing-srv-01 already had one confirmed compromise (the 0x00 cryptominer incident); two unexplained SUID binaries on this exact server are treated as a live incident-response question, not routine cleanup. DISCLOSED GROUPING: verified as CIS 7.1.13 'Ensure SUID and SGID files are reviewed', which technically sits under Section 7 (System Maintenance); grouped here under Section 1 in this profile for consolidated filesystem-hardening deployment, not because it is genuinely a Section 1 item"
 
add_control "1.1.2" \
  "Apply noexec, nosuid, and nodev mount options to non-system partitions" \
  "1" "medium" "billing-srv-01,web-srv-01,log-srv-01" \
  "Reduces post-exploitation persistence and privilege escalation options" \
  "7-mount_hardening.sh" \
  "mount | grep <partition> shows noexec,nosuid,nodev where applicable" \
  "No baseline mount option hardening currently exists; low operational risk since it only affects partitions that never legitimately execute code. Verified as CIS 1.1.2 'Configure Filesystem Partitions' against the real table of contents"
 
# --- Service minimization (CIS Section 2.1, Services, verified against real TOC) ---
add_control "2.1.22" \
  "Disable or remove unnecessary network-facing services" \
  "1" "high" "billing-srv-01" \
  "billing-srv-01's own prior compromise (0x00 cryptominer); Task 0 baseline confirmed 28 running services, several with no clear operational purpose on a headless server" \
  "8-service_minimization.sh" \
  "systemctl list-units --state=running count decreases and matches an approved services allow-list" \
  "Every additional running service is additional attack surface; a server that already suffered one compromise warrants the strictest justification standard for what stays enabled. DISCLOSED GROUPING: verified as CIS 2.1.22 'Ensure only approved services are listening on a network interface', which technically sits under Section 2 (Services); grouped here under Section 1 in this profile for consolidated deployment, not because it is genuinely a Section 1 item"
 
# --- Firewall / network exposure (CIS Section 4.1, Host Based Firewall, verified against real TOC) ---
add_control "4.1.3" \
  "Restrict MySQL to localhost-only binding and enforce default-deny host firewall" \
  "4" "high" "billing-srv-01" \
  "Direct baseline finding: MySQL listening on 0.0.0.0:3306, reachable from any address, the same exposure pattern as 1x02 Finding 006; Crimson Tide Phase 4 (direct database file exfiltration)" \
  "9-firewall_hardening.sh" \
  "ss -tulnH shows 3306 bound to 127.0.0.1 only, and ufw status shows default deny incoming" \
  "The baseline shows this database is reachable from any network address today; this is the single most literal match in this profile to the exact exfiltration method Crimson Tide is documented using. Verified as CIS 4.1.3 'Ensure ufw incoming default is configured' against the real table of contents; the MySQL-specific binding change is an application-level complement to this CIS control, not itself a numbered CIS item"
 
# --- Audit logging (CIS Section 6.2, System Auditing, verified against real TOC) ---
add_control "6.2.3.1" \
  "Deploy auditd rules for privilege escalation and sensitive file modification" \
  "6" "critical" "billing-srv-01,web-srv-01,log-srv-01" \
  "Crimson Tide Phase 3 (credential theft) and Phase 6 (domain-wide changes); GAP-004 (no detection capability)" \
  "10-auditd_configuration.sh" \
  "auditctl -l lists rules watching /etc/passwd, /etc/shadow, and sudo execution" \
  "Task 0 baseline confirms auditd is already running as a service, but a running daemon with no meaningful rules provides no actual visibility; this ensures the rules themselves exist. Verified as CIS 6.2.3.1 'Ensure changes to system administration scope (sudoers) is collected' against the real table of contents"
 
# --- Log retention (CIS Section 6.1, System Logging, verified against real TOC) ---
add_control "6.1.2.6" \
  "Configure remote log forwarding and enforce log file write-protection" \
  "6" "medium" "log-srv-01" \
  "Project context: log-srv-01 compromise would let an attacker erase all other evidence; Crimson Tide Phase 5 (backup/evidence destruction pattern)" \
  "11-log_retention.sh" \
  "rsyslog.conf shows a configured remote receiver, and local log files carry append-only protection" \
  "log-srv-01 is the most critical server to harden in this project precisely because its compromise would let an attacker erase evidence from every other system; retention and write-protection are what make its own logs trustworthy after an incident. Verified as CIS 6.1.2.6 'Ensure rsyslog is configured to send logs to a remote log host' against the real table of contents"
 
CONTROL_COUNT=${#CONTROL_ID[@]}
 
# ---------------------------------------------------------------------
# BUILD JSON
# ---------------------------------------------------------------------
{
  printf '{\n  "profile_generated": "%s",\n  "target_assets": ["billing-srv-01", "web-srv-01", "log-srv-01"],\n  "controls": [\n' \
    "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
 
  for i in "${!CONTROL_ID[@]}"; do
    printf '    {\n'
    printf '      "control_id": "%s",\n' "$(json_escape "${CONTROL_ID[$i]}")"
    printf '      "title": "%s",\n' "$(json_escape "${TITLE[$i]}")"
    printf '      "cis_section": "%s",\n' "$(json_escape "${CIS_SECTION[$i]}")"
    printf '      "severity": "%s",\n' "$(json_escape "${SEVERITY[$i]}")"
    printf '      "asset_scope": "%s",\n' "$(json_escape "${ASSET_SCOPE[$i]}")"
    printf '      "threat_mapping": "%s",\n' "$(json_escape "${THREAT_MAPPING[$i]}")"
    printf '      "implementation_task": "%s",\n' "$(json_escape "${IMPLEMENTATION_TASK[$i]}")"
    printf '      "verification_method": "%s",\n' "$(json_escape "${VERIFICATION_METHOD[$i]}")"
    printf '      "justification": "%s"\n' "$(json_escape "${JUSTIFICATION[$i]}")"
    if [ "$i" -lt $((CONTROL_COUNT - 1)) ]; then
      printf '    },\n'
    else
      printf '    }\n'
    fi
  done
 
  printf '  ]\n}\n'
} > "$OUTPUT_FILE"
 
# ---------------------------------------------------------------------
# COMPUTE SUMMARY (derived from the same arrays above, never hand-typed)
# ---------------------------------------------------------------------
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
for sev in "${SEVERITY[@]}"; do
  case "$sev" in
    critical) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
    high) HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
    medium) MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
  esac
done
 
SECTIONS_COVERED=$(printf '%s\n' "${CIS_SECTION[@]}" | sort -u | grep -c . || true)
TASKS_MAPPED=$(printf '%s\n' "${IMPLEMENTATION_TASK[@]}" | sort -u | grep -c . || true)
 
# ---------------------------------------------------------------------
# TERMINAL SUMMARY (matches the task's expected output format)
# ---------------------------------------------------------------------
echo "Controls selected: ${CONTROL_COUNT}"
echo "Critical: ${CRITICAL_COUNT}"
echo "High: ${HIGH_COUNT}"
echo "Medium: ${MEDIUM_COUNT}"
echo "CIS sections covered: ${SECTIONS_COVERED}"
echo "Mapped implementation tasks: ${TASKS_MAPPED}"
echo "Report saved to: ${OUTPUT_FILE}"
