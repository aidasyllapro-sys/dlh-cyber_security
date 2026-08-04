#!/bin/bash
#
# 8-pam_hardening.sh
#
# Goal: configure PAM to enforce password quality requirements and
# lock accounts after repeated failed authentication attempts.
#
# Threat basis: Crimson Tide Phase 2 (harvested credentials) and Phase
# 3 (Kerberoasting-style lateral movement). This project's own Task 3
# remediation queue lists both pam_pwquality (control 5.3.3.2.7) and
# pam_faillock (control 5.3.3.1.1) among its highest-priority items,
# and this project's own SSH hardening script (Task 4) already
# disabled password authentication for SSH -- but local console login
# and sudo still rely entirely on PAM, which today enforces no
# complexity, no lockout, and no history at all.
#
# SAFETY-CRITICAL DESIGN NOTE, disclosed directly: unlike password
# quality and history (which only affect a FUTURE password change and
# cannot lock anyone out of an EXISTING password), the pam_faillock
# wiring in /etc/pam.d/common-auth affects every future authentication
# attempt system-wide, including console login and sudo. A syntax
# error or wrong line order here is a genuinely more severe risk than
# any other script in this project so far, since it is not
# SSH-specific: it can affect the local console itself. This script
# therefore (a) takes a full backup of every PAM file it touches
# before making any change, (b) only ever inserts pam_faillock at the
# exact, well-established position relative to the existing
# pam_unix.so line (immediately before it for "preauth", immediately
# after it for "authfail"), never elsewhere, and (c) is idempotent:
# it checks whether its own faillock lines are already present before
# inserting them, so re-running this script never stacks duplicate
# entries, which is itself a way PAM stacks can be broken.
#
# Before trusting this script's changes, verify authentication still
# works from a SEPARATE, still-open session (do not close your
# current session first) -- the same discipline this project's own
# SSH hardening script (Task 4) required.
 
set -euo pipefail
 
BACKUP_DIR="/etc/pam-backup-$(date +%Y%m%d-%H%M%S)"
COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_PASSWORD="/etc/pam.d/common-password"
PWQUALITY_CONF="/etc/security/pwquality.conf"
FAILLOCK_CONF="/etc/security/faillock.conf"
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it modifies" >&2
  echo "system-wide PAM authentication configuration." >&2
  exit 1
fi
 
for f in "$COMMON_AUTH" "$COMMON_PASSWORD"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: ${f} not found; this does not look like a standard" >&2
    echo "Debian/Ubuntu PAM configuration. Aborting without changes." >&2
    exit 1
  fi
done
 
# ---------------------------------------------------------------------
# BACKUP EVERY FILE THIS SCRIPT WILL TOUCH
# ---------------------------------------------------------------------
mkdir -p "$BACKUP_DIR"
cp -p "$COMMON_AUTH" "$BACKUP_DIR/" || { echo "ERROR: backup failed, aborting." >&2; exit 1; }
cp -p "$COMMON_PASSWORD" "$BACKUP_DIR/" || { echo "ERROR: backup failed, aborting." >&2; exit 1; }
[ -f "$PWQUALITY_CONF" ] && cp -p "$PWQUALITY_CONF" "$BACKUP_DIR/"
[ -f "$FAILLOCK_CONF" ] && cp -p "$FAILLOCK_CONF" "$BACKUP_DIR/"
echo "[*] Backed up PAM configuration to ${BACKUP_DIR}"
 
# ---------------------------------------------------------------------
# STEP 1: INSTALL libpam-pwquality IF MISSING
# ---------------------------------------------------------------------
echo "[*] Checking libpam-pwquality..."
if dpkg -s libpam-pwquality >/dev/null 2>&1; then
  VER=$(dpkg -s libpam-pwquality 2>/dev/null | awk -F': ' '/^Version/{print $2}')
  echo "    Already installed: libpam-pwquality ${VER}"
else
  echo "    Not found, installing..."
  if apt-get install -y libpam-pwquality >/tmp/pam_install.$$ 2>&1; then
    VER=$(dpkg -s libpam-pwquality 2>/dev/null | awk -F': ' '/^Version/{print $2}')
    echo "    Installed: libpam-pwquality ${VER}"
  else
    echo "ERROR: failed to install libpam-pwquality. See /tmp/pam_install.$$ for details." >&2
    exit 1
  fi
  rm -f /tmp/pam_install.$$
fi
 
# ---------------------------------------------------------------------
# STEP 2: CONFIGURE /etc/security/pwquality.conf
# ---------------------------------------------------------------------
echo "[*] Configuring password quality (${PWQUALITY_CONF})..."
touch "$PWQUALITY_CONF"
 
set_pwquality_kv() {
  local key="$1"
  local value="$2"
  local line="${key} = ${value}"
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$PWQUALITY_CONF"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${line}|" "$PWQUALITY_CONF"
  elif grep -qE "^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=" "$PWQUALITY_CONF"; then
    sed -i -E "s|^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=.*|${line}|" "$PWQUALITY_CONF"
  else
    echo "$line" >> "$PWQUALITY_CONF"
  fi
  printf '    %-32s [SET]\n' "$line"
}
 
set_pwquality_flag() {
  # For bare flags with no "= value", e.g. reject_username
  local key="$1"
  if grep -qE "^[[:space:]]*${key}([[:space:]]|$)" "$PWQUALITY_CONF"; then
    : # already present, nothing to do
  elif grep -qE "^[[:space:]]*#[[:space:]]*${key}([[:space:]]|$)" "$PWQUALITY_CONF"; then
    sed -i -E "s|^[[:space:]]*#[[:space:]]*${key}([[:space:]]|$)|${key}\1|" "$PWQUALITY_CONF"
  else
    echo "$key" >> "$PWQUALITY_CONF"
  fi
  printf '    %-32s [SET]\n' "$key"
}
 
set_pwquality_kv "minlen" "14"
set_pwquality_kv "dcredit" "-1"
set_pwquality_kv "ucredit" "-1"
set_pwquality_kv "lcredit" "-1"
set_pwquality_kv "ocredit" "-1"
set_pwquality_kv "maxrepeat" "3"
set_pwquality_flag "reject_username"
 
# ---------------------------------------------------------------------
# STEP 3: CONFIGURE pam_faillock (account lockout)
# ---------------------------------------------------------------------
echo "[*] Configuring account lockout (pam_faillock)..."
touch "$FAILLOCK_CONF"
 
set_faillock_kv() {
  local key="$1"
  local value="$2"
  local line="${key} = ${value}"
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$FAILLOCK_CONF"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${line}|" "$FAILLOCK_CONF"
  elif grep -qE "^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=" "$FAILLOCK_CONF"; then
    sed -i -E "s|^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=.*|${line}|" "$FAILLOCK_CONF"
  else
    echo "$line" >> "$FAILLOCK_CONF"
  fi
  printf '    %-32s [SET]\n' "$line"
}
 
set_faillock_kv "deny" "5"
set_faillock_kv "unlock_time" "900"
set_faillock_kv "fail_interval" "900"
 
# Wire pam_faillock into common-auth, at the exact, well-established
# position relative to the existing pam_unix.so line. Idempotent: does
# nothing if these exact lines are already present.
if ! grep -q "pam_faillock.so preauth" "$COMMON_AUTH"; then
  sed -i -E '/pam_unix\.so/i auth\trequired\t\t\tpam_faillock.so preauth' "$COMMON_AUTH"
fi
if ! grep -q "pam_faillock.so authfail" "$COMMON_AUTH"; then
  sed -i -E '/pam_unix\.so/a auth\t[default=die]\t\t\tpam_faillock.so authfail' "$COMMON_AUTH"
fi
 
# ---------------------------------------------------------------------
# STEP 4: CONFIGURE PASSWORD HISTORY (remember=12)
# ---------------------------------------------------------------------
echo "[*] Configuring password history..."
 
# Insert pam_pwquality ahead of pam_unix.so in common-password so new
# passwords are actually checked against the quality rules configured
# above (installing the package alone does not wire it into the stack).
if ! grep -q "pam_pwquality.so" "$COMMON_PASSWORD"; then
  sed -i -E '/pam_unix\.so/i password\trequisite\t\t\tpam_pwquality.so retry=3' "$COMMON_PASSWORD"
fi
 
# Add remember=12 to the existing pam_unix.so line's own arguments,
# rather than adding a separate pam_pwhistory.so line, for maximum
# compatibility with this distribution's default PAM stack. Idempotent:
# replaces an existing remember=N rather than appending a duplicate.
if grep -qE 'pam_unix\.so.*remember=[0-9]+' "$COMMON_PASSWORD"; then
  sed -i -E 's/(pam_unix\.so.*)remember=[0-9]+/\1remember=12/' "$COMMON_PASSWORD"
elif grep -q "pam_unix.so" "$COMMON_PASSWORD"; then
  sed -i -E '/pam_unix\.so/{/pam_pwquality/!s/(pam_unix\.so[^\n]*)/\1 remember=12/}' "$COMMON_PASSWORD"
fi
printf '    %-32s [SET]\n' "remember = 12"
 
# ---------------------------------------------------------------------
# STEP 5: VALIDATE
# ---------------------------------------------------------------------
VALIDATION_OK=true
grep -q "pam_faillock.so preauth" "$COMMON_AUTH" || VALIDATION_OK=false
grep -q "pam_faillock.so authfail" "$COMMON_AUTH" || VALIDATION_OK=false
grep -q "pam_pwquality.so" "$COMMON_PASSWORD" || VALIDATION_OK=false
grep -qE 'remember=12' "$COMMON_PASSWORD" || VALIDATION_OK=false
grep -qE "^minlen = 14" "$PWQUALITY_CONF" || VALIDATION_OK=false
grep -qE "^deny = 5" "$FAILLOCK_CONF" || VALIDATION_OK=false
 
if [ "$VALIDATION_OK" != true ]; then
  echo "ERROR: post-change validation failed. Restoring backup from ${BACKUP_DIR}." >&2
  cp -p "${BACKUP_DIR}/common-auth" "$COMMON_AUTH" || true
  cp -p "${BACKUP_DIR}/common-password" "$COMMON_PASSWORD" || true
  [ -f "${BACKUP_DIR}/pwquality.conf" ] && cp -p "${BACKUP_DIR}/pwquality.conf" "$PWQUALITY_CONF" || true
  [ -f "${BACKUP_DIR}/faillock.conf" ] && cp -p "${BACKUP_DIR}/faillock.conf" "$FAILLOCK_CONF" || true
  echo "Backup restored. Investigate before re-running. Do not close your" >&2
  echo "current session until you have confirmed authentication works." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
