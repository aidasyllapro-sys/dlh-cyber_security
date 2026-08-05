#!/bin/bash
#
# 15-validation.sh
#
# Read-only, independent verification that every hardening control from
# Tasks 4-13 is still in its expected state -- the recurring drift check
# James Chen runs every Monday. This script makes NO changes to the
# system's configuration, ever: it only reads state and reports
# PASS/FAIL for each control, both to the terminal and to
# validation_results.json (its own evidence file, consumed by this
# project's Task 17 compliance bundle), then exits 0 if everything
# passed or 1 if anything failed.
 
set -euo pipefail
# Every risky read (sshd -T, grep against a config file, aa-status
# parsing) happens inside a helper function captured via command
# substitution ($(...)), which runs in its own subshell. If a command
# inside one of those subshells fails under -e, only that subshell
# exits early, yielding an empty captured value -- which check() below
# already treats correctly as a FAIL, not a crash. No unguarded risky
# command sits directly in this script's own top-level flow.
 
VALIDATION_JSON="./validation_results.json"
PASS_COUNT=0
FAIL_COUNT=0
CHECK_ENTRIES=()
 
# ---------------------------------------------------------------------
# JSON ESCAPE HELPER
# ---------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}
 
# ---------------------------------------------------------------------
# CHECK HELPER: compares an actual value to an expected one, prints
# [PASS]/[FAIL] in the task's exact format, tracks totals, and records
# a structured entry for validation_results.json. Never modifies
# system state; every "actual" value passed in must already have been
# read by the caller.
# ---------------------------------------------------------------------
check() {
  local label="$1" actual="$2" expected="$3" status
  if [ "$actual" = "$expected" ]; then
    echo "[PASS] ${label} = ${actual}"
    status="PASS"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "[FAIL] ${label} = ${actual} (expected: ${expected})"
    status="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
  CHECK_ENTRIES+=("{\"control\":\"$(json_escape "$label")\",\"actual\":\"$(json_escape "$actual")\",\"expected\":\"$(json_escape "$expected")\",\"status\":\"${status}\"}")
}
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since several" >&2
  echo "checks (sshd -T, auditctl -l) require it to read complete" >&2
  echo "system state." >&2
  exit 1
fi
 
# =======================================================================
# TASK 4: SSH HARDENING
# =======================================================================
SSH_EFFECTIVE=""
if command -v sshd >/dev/null 2>&1; then
  SSH_EFFECTIVE=$(sshd -T 2>/dev/null || true)
fi
 
get_ssh() {
  local directive="$1"
  printf '%s\n' "$SSH_EFFECTIVE" | grep -i "^${directive} " | awk '{$1=""; print $0}' | sed 's/^ //' | head -1
}
 
check "PermitRootLogin" "$(get_ssh permitrootlogin)" "no"
check "PasswordAuthentication" "$(get_ssh passwordauthentication)" "no"
check "PermitEmptyPasswords" "$(get_ssh permitemptypasswords)" "no"
check "X11Forwarding" "$(get_ssh x11forwarding)" "no"
check "MaxAuthTries" "$(get_ssh maxauthtries)" "3"
check "ClientAliveInterval" "$(get_ssh clientaliveinterval)" "300"
check "ClientAliveCountMax" "$(get_ssh clientalivecountmax)" "2"
check "LoginGraceTime" "$(get_ssh logingracetime)" "60"
 
# =======================================================================
# TASK 5: KERNEL / SYSCTL HARDENING
# =======================================================================
get_sysctl() {
  local key="$1"
  local path="/proc/sys/${key//./\/}"
  if [ -r "$path" ]; then
    tr -d '[:space:]' < "$path"
  else
    echo "unavailable"
  fi
}
 
check "net.ipv4.ip_forward" "$(get_sysctl net.ipv4.ip_forward)" "0"
check "net.ipv4.conf.all.accept_redirects" "$(get_sysctl net.ipv4.conf.all.accept_redirects)" "0"
check "net.ipv4.conf.all.send_redirects" "$(get_sysctl net.ipv4.conf.all.send_redirects)" "0"
check "net.ipv4.conf.all.accept_source_route" "$(get_sysctl net.ipv4.conf.all.accept_source_route)" "0"
check "net.ipv4.conf.all.log_martians" "$(get_sysctl net.ipv4.conf.all.log_martians)" "1"
check "net.ipv4.tcp_syncookies" "$(get_sysctl net.ipv4.tcp_syncookies)" "1"
check "net.ipv4.icmp_echo_ignore_broadcasts" "$(get_sysctl net.ipv4.icmp_echo_ignore_broadcasts)" "1"
check "kernel.randomize_va_space" "$(get_sysctl kernel.randomize_va_space)" "2"
check "fs.suid_dumpable" "$(get_sysctl fs.suid_dumpable)" "0"
check "kernel.dmesg_restrict" "$(get_sysctl kernel.dmesg_restrict)" "1"
check "kernel.kptr_restrict" "$(get_sysctl kernel.kptr_restrict)" "2"
 
# =======================================================================
# TASK 6: FILESYSTEM HARDENING
# =======================================================================
# Spot-check the two specific unauthorized SUID binaries this project's
# own Task 0 baseline found on billing-srv-01; PASS means they no
# longer carry the SUID bit (either removed entirely or bit stripped).
check_no_suid() {
  local path="$1"
  if [ ! -e "$path" ]; then
    echo "absent"
  elif [ -u "$path" ]; then
    echo "still-suid"
  else
    echo "no-suid"
  fi
}
check "SUID /usr/local/bin/oldtool" "$(check_no_suid /usr/local/bin/oldtool)" "no-suid"
check "SUID /opt/legacy/setuid-app" "$(check_no_suid /opt/legacy/setuid-app)" "no-suid"
 
if [ -f /etc/cron.allow ]; then
  check "cron.allow exists" "yes" "yes"
else
  check "cron.allow exists" "no" "yes"
fi
 
# =======================================================================
# TASK 7: SERVICE MINIMIZATION
# =======================================================================
check_active() {
  local svc="$1"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$svc" 2>/dev/null; then
    echo "active"
  else
    echo "inactive"
  fi
}
for svc in ssh apache2 mysql auditd cron rsyslog systemd-timesyncd; do
  check "${svc}.service" "$(check_active "$svc")" "active"
done
# Spot-check one explicitly-disabled service from Task 7's own example.
check "avahi-daemon.service" "$(check_active avahi-daemon)" "inactive"
 
# =======================================================================
# TASK 8: PAM HARDENING
# =======================================================================
get_pwquality() {
  local key="$1"
  grep -E "^[[:space:]]*${key}[[:space:]]*=" /etc/security/pwquality.conf 2>/dev/null \
    | tail -1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}'
}
check "pwquality.minlen" "$(get_pwquality minlen)" "14"
check "pwquality.maxrepeat" "$(get_pwquality maxrepeat)" "3"
 
get_faillock() {
  local key="$1"
  grep -E "^[[:space:]]*${key}[[:space:]]*=" /etc/security/faillock.conf 2>/dev/null \
    | tail -1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print $2}'
}
check "faillock.deny" "$(get_faillock deny)" "5"
check "faillock.unlock_time" "$(get_faillock unlock_time)" "900"
 
if grep -q "pam_faillock.so preauth" /etc/pam.d/common-auth 2>/dev/null; then
  check "pam_faillock wired into common-auth" "yes" "yes"
else
  check "pam_faillock wired into common-auth" "no" "yes"
fi
 
if grep -qE 'pam_unix\.so.*remember=12' /etc/pam.d/common-password 2>/dev/null; then
  check "password history remember" "12" "12"
else
  check "password history remember" "$(grep -oE 'remember=[0-9]+' /etc/pam.d/common-password 2>/dev/null | head -1 | cut -d= -f2)" "12"
fi
 
# =======================================================================
# TASK 9: APPARMOR
# =======================================================================
check "apparmor.service" "$(check_active apparmor)" "active"
 
apparmor_mode() {
  local bin_path="$1"
  local status_out
  status_out=$(aa-status 2>/dev/null || true)
  if printf '%s\n' "$status_out" | awk '/profiles are in enforce mode/,/^$/' | grep -qF "$bin_path"; then
    echo "enforce"
  elif printf '%s\n' "$status_out" | awk '/profiles are in complain mode/,/^$/' | grep -qF "$bin_path"; then
    echo "complain"
  else
    echo "none"
  fi
}
check "AppArmor /usr/sbin/apache2" "$(apparmor_mode /usr/sbin/apache2)" "enforce"
check "AppArmor /usr/sbin/mysqld" "$(apparmor_mode /usr/sbin/mysqld)" "enforce"
 
# =======================================================================
# TASK 10: AUDITD
# =======================================================================
check "auditd.service" "$(check_active auditd)" "active"
 
check_audit_rule() {
  local key="$1"
  if command -v auditctl >/dev/null 2>&1 && auditctl -l 2>/dev/null | grep -q "key=${key}"; then
    echo "present"
  else
    echo "absent"
  fi
}
check "audit rule key=identity" "$(check_audit_rule identity)" "present"
check "audit rule key=priv_esc" "$(check_audit_rule priv_esc)" "present"
check "audit rule key=sshd_config" "$(check_audit_rule sshd_config)" "present"
 
# =======================================================================
# TASK 12: RSYSLOG / LOG ROTATION
# =======================================================================
if [ -f /etc/rsyslog.d/49-meddefense.conf ] && grep -q "auth,authpriv" /etc/rsyslog.d/49-meddefense.conf 2>/dev/null; then
  check "rsyslog auth routing configured" "yes" "yes"
else
  check "rsyslog auth routing configured" "no" "yes"
fi
 
if [ -f /etc/logrotate.d/meddefense-logs ] && grep -q "rotate 90" /etc/logrotate.d/meddefense-logs 2>/dev/null; then
  check "auth.log rotation retention" "90" "90"
else
  check "auth.log rotation retention" "not-90" "90"
fi
 
if [ -f /var/log/auth.log ]; then
  AUTH_PERMS=$(stat -c "%a %U:%G" /var/log/auth.log 2>/dev/null)
  check "auth.log permissions" "$AUTH_PERMS" "640 root:adm"
fi
 
# =======================================================================
# TASK 13: FIREWALL
# =======================================================================
if command -v ufw >/dev/null 2>&1; then
  UFW_STATUS_LINE=$(ufw status verbose 2>/dev/null || true)
  UFW_ACTIVE=$(printf '%s\n' "$UFW_STATUS_LINE" | head -1 | awk '{print $2}')
  check "UFW status" "${UFW_ACTIVE:-inactive}" "active"
 
  DEFAULT_IN=$(printf '%s\n' "$UFW_STATUS_LINE" | grep -i "^Default:" | grep -oE 'deny \(incoming\)|allow \(incoming\)' | awk '{print $1}')
  check "Default incoming" "${DEFAULT_IN:-unknown}" "deny"
 
  DEFAULT_OUT=$(printf '%s\n' "$UFW_STATUS_LINE" | grep -i "^Default:" | grep -oE 'deny \(outgoing\)|allow \(outgoing\)' | awk '{print $1}')
  check "Default outgoing" "${DEFAULT_OUT:-unknown}" "allow"
else
  check "UFW status" "not-installed" "active"
fi
 
# =======================================================================
# WRITE validation_results.json
# =======================================================================
{
  printf '{\n  "run_date": "%s",\n  "checks": [\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  total=${#CHECK_ENTRIES[@]}
  for i in "${!CHECK_ENTRIES[@]}"; do
    printf '    %s' "${CHECK_ENTRIES[$i]}"
    if [ "$i" -lt $((total - 1)) ]; then printf ',\n'; else printf '\n'; fi
  done
  printf '  ],\n  "passed": %d,\n  "failed": %d\n}\n' "$PASS_COUNT" "$FAIL_COUNT"
} > "$VALIDATION_JSON"
 
# =======================================================================
# SUMMARY / EXIT CODE
# =======================================================================
echo ""
echo "Checks passed: ${PASS_COUNT}"
echo "Checks failed: ${FAIL_COUNT}"
 
if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
