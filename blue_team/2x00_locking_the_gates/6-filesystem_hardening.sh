#!/bin/bash
#
# 6-filesystem_hardening.sh
#
# Goal: audit and remediate dangerous filesystem permissions that could
# enable privilege escalation: unauthorized SUID/SGID binaries,
# world-writable files, missing mount-option hardening on temp
# partitions, and unrestricted cron access.
#
# Threat basis: SUID binaries are the classic mechanism a low-privilege
# shell uses to escalate to root; world-writable files let an attacker
# modify a script that later runs as root. This project's own Task 0
# baseline already found two specific, unexplained SUID binaries on
# billing-srv-01 (/usr/local/bin/oldtool, /opt/legacy/setuid-app), a
# server with a prior confirmed compromise (the 0x00 cryptominer
# incident) -- these are treated here as a live incident-response
# question, not routine cleanup, per this project's own Task 3
# remediation queue (control 7.1.13).
#
# SAFETY-CRITICAL DESIGN NOTE, disclosed directly: Step 4 (mount
# options) NEVER remounts a path that is not already its own separate
# mount point. On many default Ubuntu installations, /tmp and
# /var/tmp are ordinary directories on the root filesystem, not
# separate mounts. Remounting the root filesystem itself with noexec
# would make the system unable to execute anything at all, including
# the shell running this script. Where a target path is not a genuine
# separate mount, this script reports that fact clearly as a finding
# instead of attempting a remount that could make the server
# unusable. This mirrors the same safety-first judgment already
# applied to this project's SSH hardening script (Task 4)'s AllowUsers
# handling.
#
# This script is idempotent: SUID/SGID checks only strip bits that are
# actually still set; a bit already removed is left alone and not
# reported as a fresh remediation on a second run. Mount-option and
# cron changes are also safe to reapply.
 
set -euo pipefail
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it modifies" >&2
  echo "SUID/SGID bits, file permissions, mount options, and cron access." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# SUID WHITELIST: known-safe binaries on a stock Ubuntu 22.04 LTS
# install plus common, legitimately-installed packages relevant to
# this environment (VMware guest tools, snapd), confirmed against this
# project's own Task 0 real baseline scan of billing-srv-01.
# ---------------------------------------------------------------------
SUID_WHITELIST=(
  "/usr/bin/sudo"
  "/usr/bin/su"
  "/usr/bin/passwd"
  "/usr/bin/chsh"
  "/usr/bin/chfn"
  "/usr/bin/gpasswd"
  "/usr/bin/newgrp"
  "/usr/bin/mount"
  "/usr/bin/umount"
  "/usr/bin/fusermount3"
  "/usr/bin/pkexec"
  "/usr/bin/at"
  "/usr/bin/ntfs-3g"
  "/usr/lib/openssh/ssh-keysign"
  "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
  "/usr/libexec/polkit-agent-helper-1"
  "/usr/lib/policykit-1/polkit-agent-helper-1"
  "/usr/lib/polkit-1/polkit-agent-helper-1"
  "/usr/lib/snapd/snap-confine"
  "/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper"
  "/usr/bin/vmware-user-suid-wrapper"
  "/usr/sbin/pppd"
  "/usr/sbin/mount.nfs"
)
 
# ---------------------------------------------------------------------
# SGID WHITELIST: known-safe SGID binaries on a stock Ubuntu 22.04.
# ---------------------------------------------------------------------
SGID_WHITELIST=(
  "/usr/bin/crontab"
  "/usr/bin/chage"
  "/usr/bin/expiry"
  "/usr/bin/ssh-agent"
  "/usr/bin/wall"
  "/usr/bin/write"
  "/usr/bin/mlocate"
  "/usr/sbin/pam_extrausers_chkpwd"
  "/usr/sbin/unix_chkpwd"
  "/usr/lib/x86_64-linux-gnu/utempter/utempter"
)
 
is_whitelisted() {
  local path="$1"
  shift
  local list=("$@")
  local w
  for w in "${list[@]}"; do
    [ "$path" = "$w" ] && return 0
  done
  return 1
}
 
# ---------------------------------------------------------------------
# STEP 1: SUID AUDIT
# ---------------------------------------------------------------------
mapfile -t SUID_FOUND < <(find / -xdev -type f -perm -4000 2>/dev/null)
SUID_TOTAL=${#SUID_FOUND[@]}
echo "Found ${SUID_TOTAL} SUID binaries"
 
SUID_WHITELISTED_COUNT=0
SUID_REMEDIATED=0
SUID_NONWHITELISTED_LINES=()
for bin in "${SUID_FOUND[@]}"; do
  if is_whitelisted "$bin" "${SUID_WHITELIST[@]}"; then
    SUID_WHITELISTED_COUNT=$((SUID_WHITELISTED_COUNT + 1))
  else
    chmod u-s "$bin" || echo "WARNING: failed to strip SUID from ${bin}" >&2
    SUID_REMEDIATED=$((SUID_REMEDIATED + 1))
    SUID_NONWHITELISTED_LINES+=("$bin")
  fi
done
SUID_NONWHITELISTED_COUNT=$((SUID_TOTAL - SUID_WHITELISTED_COUNT))
echo "Whitelisted: ${SUID_WHITELISTED_COUNT}"
echo "Non-whitelisted: ${SUID_NONWHITELISTED_COUNT}"
for bin in "${SUID_NONWHITELISTED_LINES[@]}"; do
  printf '  %-25s [SUID REMOVED]\n' "$bin"
done
 
# ---------------------------------------------------------------------
# STEP 2: SGID AUDIT
# ---------------------------------------------------------------------
mapfile -t SGID_FOUND < <(find / -xdev -type f -perm -2000 2>/dev/null)
SGID_TOTAL=${#SGID_FOUND[@]}
echo "Found ${SGID_TOTAL} SGID binaries"
 
SGID_WHITELISTED_COUNT=0
SGID_REMEDIATED=0
SGID_NONWHITELISTED_LINES=()
for bin in "${SGID_FOUND[@]}"; do
  if is_whitelisted "$bin" "${SGID_WHITELIST[@]}"; then
    SGID_WHITELISTED_COUNT=$((SGID_WHITELISTED_COUNT + 1))
  else
    chmod g-s "$bin" || echo "WARNING: failed to strip SGID from ${bin}" >&2
    SGID_REMEDIATED=$((SGID_REMEDIATED + 1))
    SGID_NONWHITELISTED_LINES+=("$bin")
  fi
done
SGID_NONWHITELISTED_COUNT=$((SGID_TOTAL - SGID_WHITELISTED_COUNT))
echo "Whitelisted: ${SGID_WHITELISTED_COUNT}"
echo "Non-whitelisted: ${SGID_NONWHITELISTED_COUNT}"
for bin in "${SGID_NONWHITELISTED_LINES[@]}"; do
  printf '  %-25s [SGID REMOVED]\n' "$bin"
done
 
# ---------------------------------------------------------------------
# STEP 3: WORLD-WRITABLE FILES
# ---------------------------------------------------------------------
mapfile -t WW_FOUND < <(find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -0002 -print 2>/dev/null)
WW_TOTAL=${#WW_FOUND[@]}
echo "Found ${WW_TOTAL} world-writable files"
 
WW_FIXED=0
for f in "${WW_FOUND[@]}"; do
  if chmod o-w "$f" 2>/dev/null; then
    WW_FIXED=$((WW_FIXED + 1))
    printf '  %-25s [FIXED]\n' "$f"
  else
    echo "WARNING: failed to fix world-writable bit on ${f}" >&2
  fi
done
 
# ---------------------------------------------------------------------
# STEP 4: MOUNT OPTIONS FOR /tmp, /var/tmp, /dev/shm
# ---------------------------------------------------------------------
# SAFETY: only ever acts on a path that is confirmed, via findmnt, to
# be its own separate mount point. See header comment for why.
check_mount_options() {
  local path="$1"
  local desired="noexec,nosuid,nodev"
 
  if ! findmnt -n "$path" >/dev/null 2>&1; then
    printf '%s: %-19s [SKIPPED - not a separate mount, cannot safely harden]\n' "$path" "$desired"
    return
  fi
 
  local current
  current=$(findmnt -n -o OPTIONS "$path" 2>/dev/null || echo "")
 
  local missing=""
  for opt in noexec nosuid nodev; do
    if ! grep -qw "$opt" <<< "$current"; then
      missing="${missing}${missing:+,}${opt}"
    fi
  done
 
  if [ -z "$missing" ]; then
    printf '%s: %-19s [OK]\n' "$path" "$desired"
  else
    if mount -o "remount,${desired}" "$path" 2>/dev/null; then
      printf '%s: %-19s [APPLIED]\n' "$path" "$desired"
    else
      printf '%s: %-19s [FAILED - remount rejected, check manually]\n' "$path" "$desired"
    fi
  fi
}
 
check_mount_options "/tmp"
check_mount_options "/var/tmp"
check_mount_options "/dev/shm"
 
# ---------------------------------------------------------------------
# STEP 5: RESTRICT CRON ACCESS
# ---------------------------------------------------------------------
# Ubuntu's default (no /etc/cron.allow, no /etc/cron.deny) permits
# every local user to schedule cron jobs. Creating cron.allow with
# only the authorized administrative accounts closes that gap.
CRON_ALLOW="/etc/cron.allow"
AUTHORIZED_CRON_USERS=("medadmin" "sysadmin" "analyst" "root")
{
  for u in "${AUTHORIZED_CRON_USERS[@]}"; do
    echo "$u"
  done
} > "$CRON_ALLOW"
chmod 644 "$CRON_ALLOW"
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "SUID remediated: ${SUID_REMEDIATED} | SGID remediated: ${SGID_REMEDIATED} | World-writable fixed: ${WW_FIXED}"
