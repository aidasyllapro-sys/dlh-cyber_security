#!/bin/bash
#
# 7-service_minimization.sh
#
# Goal: reduce billing-srv-01's attack surface to only the services
# MedDefense operations actually require, stopping and disabling
# everything else.
#
# Threat basis: CIS Benchmark Section 2 (Services). Every running
# service is a potential entry point; 1x02 Finding 006 already showed
# MySQL exposed network-wide, and this project's own Task 0 baseline
# confirmed billing-srv-01 running services including ModemManager and
# snmpd that a headless database/web server has no legitimate need
# for. This project's own Task 3 remediation queue lists service
# minimization as control 2.1.22.
#
# SAFETY-CRITICAL DESIGN NOTE, disclosed directly: this script
# maintains TWO lists, not one. The MEDDEFENSE_WHITELIST below is the
# literal 9-service business/security requirement the task specifies.
# A separate SYSTEM_PROTECTED list holds core OS infrastructure
# services (systemd-networkd, systemd-resolved, systemd-logind,
# dbus, polkit, systemd-journald, systemd-udevd, getty@tty1, and any
# per-session user@*.service instance) that this script will NEVER
# stop or disable, even though they are not MedDefense business
# requirements. Disabling dbus or systemd-networkd, for example, could
# break the system's own ability to function or be reached at all,
# which would be a far worse outcome than leaving one extra service
# running. A service is only stopped/disabled if it appears in
# NEITHER list. This mirrors the same safety-first judgment already
# applied to this project's SSH (Task 4) and filesystem (Task 6)
# hardening scripts.
#
# This script is idempotent: a service already stopped/disabled is
# left alone (not re-reported as a fresh action) on a second run.
 
set -euo pipefail
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it stops" >&2
  echo "and disables system services." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# MEDDEFENSE WHITELIST: the 9 services billing-srv-01 actually needs.
# ---------------------------------------------------------------------
MEDDEFENSE_WHITELIST=(
  "ssh.service"                 # remote administration; hardened in Task 4
  "apache2.service"             # serves the patient portal web application
  "mysql.service"                # billing/patient database backend
  "ufw.service"                  # host firewall, default-deny enforcement (Task 3 control 4.1.3)
  "auditd.service"               # security event logging (Task 3 control 6.2.3.1)
  "apparmor.service"             # mandatory access control confinement of exposed services
  "cron.service"                 # scheduled maintenance and backup jobs
  "rsyslog.service"               # local and remote log forwarding (Task 3 control 6.1.2.6)
  "systemd-timesyncd.service"     # accurate clock, required for audit log integrity and TLS validation
)
 
# ---------------------------------------------------------------------
# SYSTEM_PROTECTED: core OS infrastructure, never touched regardless
# of MedDefense business need. See header comment for why.
# ---------------------------------------------------------------------
SYSTEM_PROTECTED_EXACT=(
  "systemd-journald.service"
  "systemd-logind.service"
  "systemd-networkd.service"
  "systemd-resolved.service"
  "systemd-udevd.service"
  "dbus.service"
  "polkit.service"
  "getty@tty1.service"
)
# Pattern-based protection for per-session instances (e.g. user@1000.service)
is_protected() {
  local svc="$1"
  local p
  for p in "${SYSTEM_PROTECTED_EXACT[@]}"; do
    [ "$svc" = "$p" ] && return 0
  done
  case "$svc" in
    user@*.service) return 0 ;;
  esac
  return 1
}
 
is_whitelisted() {
  local svc="$1"
  local w
  for w in "${MEDDEFENSE_WHITELIST[@]}"; do
    [ "$svc" = "$w" ] && return 0
  done
  return 1
}
 
# ---------------------------------------------------------------------
# STEP 1: SCAN ENABLED SERVICES
# ---------------------------------------------------------------------
echo "[*] Scanning enabled services..."
mapfile -t ENABLED_SERVICES < <(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}')
BEFORE_COUNT=${#ENABLED_SERVICES[@]}
echo "    Enabled services found: ${BEFORE_COUNT}"
 
# ---------------------------------------------------------------------
# STEP 2 & 3: COMPARE AND DISABLE NON-WHITELISTED, NON-PROTECTED SERVICES
# ---------------------------------------------------------------------
echo "[*] Comparing against MedDefense whitelist (${#MEDDEFENSE_WHITELIST[@]} required services)..."
 
DISABLED_COUNT=0
for svc in "${ENABLED_SERVICES[@]}"; do
  if is_whitelisted "$svc" || is_protected "$svc"; then
    continue
  fi
  if systemctl stop "$svc" 2>/dev/null; then
    STOP_RESULT="STOPPED"
  else
    STOP_RESULT="STOP-FAILED"
  fi
  if systemctl disable "$svc" >/dev/null 2>&1; then
    DISABLE_RESULT="DISABLED"
  else
    DISABLE_RESULT="DISABLE-FAILED"
  fi
  printf '  %-25s [%s] [%s]\n' "$svc" "$STOP_RESULT" "$DISABLE_RESULT"
  DISABLED_COUNT=$((DISABLED_COUNT + 1))
done
 
# ---------------------------------------------------------------------
# STEP 4: VERIFY REQUIRED SERVICES ARE RUNNING
# ---------------------------------------------------------------------
ACTIVE_COUNT=0
for svc in "${MEDDEFENSE_WHITELIST[@]}"; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    printf '  %-25s [ACTIVE]\n' "$svc"
    ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
  else
    printf '  %-25s [NOT ACTIVE - investigate]\n' "$svc"
  fi
done
 
# ---------------------------------------------------------------------
# STEP 5: BEFORE/AFTER SUMMARY
# ---------------------------------------------------------------------
AFTER_COUNT=$((BEFORE_COUNT - DISABLED_COUNT))
echo "Before: ${BEFORE_COUNT} | After: ${AFTER_COUNT} | Disabled: ${DISABLED_COUNT}"
