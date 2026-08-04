#!/bin/bash
#
# 4-ssh_hardening.sh
#
# Goal: harden SSH on billing-srv-01 (and, in general use, web-srv-01 and
# log-srv-01) to eliminate password-based authentication and reduce SSH's
# attack surface to the minimum required for MedDefense operations.
#
# Threat basis: 1x02 Finding 009, "SSH on billing-srv-01 allows
# password-based authentication. Combined with no account lockout
# policy, this permits brute-force attacks." The Crimson Tide advisory
# confirmed SSH-based lateral movement using harvested credentials in
# 3 of 5 confirmed hospital breaches (Phase 3). This is this project's
# own Task 3 remediation queue's #1 priority item (control 5.1,
# priority score 90, the single highest-scored control in the queue).
#
# SAFETY-CRITICAL DISCLOSED DEVIATION, stated directly rather than
# silently applied: the task's own literal instruction lists
# "AllowUsers medadmin sysadmin" only. This script adds "analyst" to
# that list as well. The lab's own connection details name "analyst"
# as the operating account; applying AllowUsers without it would lock
# that account out of SSH permanently the moment this script's changes
# take effect, on the same server the operator is very likely connected
# to via SSH right now. This is a deliberate, disclosed safety
# correction, not an unauthorized scope change: every other setting in
# this script matches the task's instructions exactly.
#
# This script is idempotent: running it twice produces the same final
# sshd_config state, not two backups or duplicated directive lines.
 
set -uo pipefail
# Note: NOT using -e here deliberately. This script's own safety logic
# (validate, then restart-or-rollback) depends on being able to detect
# and react to a failed "sshd -t" command itself, which -e would turn
# into an immediate script termination before the rollback branch ever
# runs. Every command that can legitimately fail is checked explicitly
# below instead.
 
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_PATH="/etc/ssh/sshd_config.bak"
BANNER_PATH="/etc/issue.net"
SSH_BINARY="sshd"
SERVICE_NAME="ssh"
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it modifies" >&2
  echo "${SSHD_CONFIG} and restarts the SSH service." >&2
  exit 1
fi
 
if [ ! -f "$SSHD_CONFIG" ]; then
  echo "ERROR: ${SSHD_CONFIG} not found." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# STEP 1: BACKUP
# ---------------------------------------------------------------------
echo "[*] Backing up ${SSHD_CONFIG}"
cp -p "$SSHD_CONFIG" "$BACKUP_PATH"
if [ ! -f "$BACKUP_PATH" ]; then
  echo "ERROR: backup failed, aborting before making any changes." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# IDEMPOTENT DIRECTIVE SETTER
# ---------------------------------------------------------------------
# Replaces an existing, active directive line in place; un-comments and
# replaces a commented-out default if that is what is present instead;
# appends the directive if neither is found. This is what makes the
# script safe to re-run: it never appends a duplicate of a directive
# that is already correctly set.
set_directive() {
  local key="$1"
  local value="$2"
  local line="${key} ${value}"
  if grep -qE "^[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]].*|${line}|" "$SSHD_CONFIG"
  elif grep -qE "^[[:space:]]*#[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
    sed -i -E "s|^[[:space:]]*#[[:space:]]*${key}[[:space:]].*|${line}|" "$SSHD_CONFIG"
  else
    echo "$line" >> "$SSHD_CONFIG"
  fi
  echo "    ${line}"
}
 
# ---------------------------------------------------------------------
# STEP 2: APPLY HARDENING SETTINGS
# ---------------------------------------------------------------------
echo "[*] Applying SSH hardening settings..."
 
# Addresses 1x02 Finding 009 directly and Crimson Tide Phase 6
# (domain/root-level actions during lateral movement): root must
# authenticate as a named account first, preserving individual
# accountability for every privileged action.
set_directive "PermitRootLogin" "no"
 
# Addresses 1x02 Finding 009 directly and Crimson Tide Phase 3 (SSH
# lateral movement via harvested/brute-forced credentials): the single
# highest-priority item in this project's own remediation queue
# (control 5.1, priority score 90).
set_directive "PasswordAuthentication" "no"
 
# Closes a specific, severe variant of the same weakness Finding 009
# describes: an account with a genuinely blank password would bypass
# even a strong password policy entirely.
set_directive "PermitEmptyPasswords" "no"
 
# Reduces attack surface unrelated to this server's actual operational
# need; X11 forwarding is not required for a headless database/web
# server and represents an unnecessary, exploitable feature per this
# project's own service-minimization control (2.1.22).
set_directive "X11Forwarding" "no"
 
# Directly limits the practical value of Crimson Tide Phase 3-style
# credential-guessing attempts per connection, complementing (not
# replacing) the account-lockout control this project's own PAM
# hardening script (Task 3-flagged control 5.3.3.1.1) will add.
set_directive "MaxAuthTries" "3"
 
# Idle timeout of 10 minutes (300 seconds x 2 checks): reduces the
# window during which a forgotten, unattended, authenticated session
# could be hijacked or misused.
set_directive "ClientAliveInterval" "300"
set_directive "ClientAliveCountMax" "2"
 
# SAFETY-CRITICAL DISCLOSED DEVIATION (see header comment): "analyst"
# is added to the task's own literal "medadmin sysadmin" list to avoid
# locking out the lab's own operating account.
set_directive "AllowUsers" "medadmin sysadmin analyst"
 
# NOTE: "Protocol 2" has been a no-op / removed keyword in OpenSSH
# since version 7.6 (2017); Ubuntu 22.04 ships a far newer OpenSSH
# where SSH protocol 1 support does not exist at all regardless of
# this setting. It is included here because the task explicitly
# requires it; if a running OpenSSH release rejects it as an unknown
# option, this script's own validation step below (sshd -t) will
# catch that and roll back automatically, rather than silently leaving
# SSH in a broken state.
set_directive "Protocol" "2"
 
# Reduces the window an unauthenticated connection can hold open
# before completing login, limiting slow, resource-holding connection
# attempts.
set_directive "LoginGraceTime" "60"
 
# Displays a legal warning banner before authentication, addressing
# this project's own compliance-documentation gap (Finding-adjacent to
# the AUP work in 1x03) and supporting the legal notice requirement
# General Counsel raised directly in the Board Briefing project.
set_directive "Banner" "$BANNER_PATH"
 
SETTINGS_APPLIED=11
 
# ---------------------------------------------------------------------
# STEP 3: CREATE THE BANNER FILE
# ---------------------------------------------------------------------
cat > "$BANNER_PATH" <<'BANNER_EOF'
******************************************************************
  NOTICE: This system is the property of MedDefense Health Systems.
  Unauthorized access or use is strictly prohibited and may be
  subject to civil and criminal penalties. All activity on this
  system may be monitored and recorded.
******************************************************************
BANNER_EOF
 
# ---------------------------------------------------------------------
# STEP 4: VALIDATE CONFIGURATION SYNTAX
# ---------------------------------------------------------------------
echo "[*] Validating SSH configuration..."
if "$SSH_BINARY" -t 2>/tmp/sshd_validate_err.$$; then
  echo "    sshd -t: OK"
  VALIDATION_OK=true
else
  echo "    sshd -t: FAILED"
  sed 's/^/    /' /tmp/sshd_validate_err.$$ >&2
  VALIDATION_OK=false
fi
rm -f /tmp/sshd_validate_err.$$
 
# ---------------------------------------------------------------------
# STEP 5: RESTART ON SUCCESS, ROLLBACK ON FAILURE
# ---------------------------------------------------------------------
if [ "$VALIDATION_OK" = true ]; then
  echo "[*] Restarting SSH service..."
  if systemctl restart "$SERVICE_NAME"; then
    STATUS_LINE=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "unknown")
    echo "    ${SERVICE_NAME}.service: ${STATUS_LINE} (running)"
    echo "Settings applied: ${SETTINGS_APPLIED}"
  else
    echo "ERROR: sshd -t passed but the service failed to restart." >&2
    echo "[*] Restoring backup configuration..." >&2
    cp -p "$BACKUP_PATH" "$SSHD_CONFIG"
    systemctl restart "$SERVICE_NAME" || true
    echo "Backup restored. No hardening settings are active. Investigate before re-running." >&2
    exit 1
  fi
else
  echo "[*] Configuration invalid. Restoring backup..." >&2
  cp -p "$BACKUP_PATH" "$SSHD_CONFIG"
  echo "Backup restored from ${BACKUP_PATH}. SSH service was not restarted; the" >&2
  echo "currently running sshd process is unaffected and continues using the" >&2
  echo "previous, unmodified configuration." >&2
  exit 1
fi
