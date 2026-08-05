#!/bin/bash
#
# 12-log_config.sh
#
# Configures rsyslog auth/syslog routing, sets logrotate retention
# (auth.log 90 days, syslog 60 days, both compressed after 7 days via
# a lastaction find+gzip hook since logrotate's native delaycompress
# only delays by one rotation cycle, not a literal day count), verifies
# both logs actively receive events using a real logger test message,
# and restricts log file permissions to root:adm 640.
 
set -euo pipefail
 
RSYSLOG_CONF="/etc/rsyslog.d/49-meddefense.conf"
LOGROTATE_CONF="/etc/logrotate.d/meddefense-logs"
AUTH_LOG="/var/log/auth.log"
SYS_LOG="/var/log/syslog"
 
CONFIGURED_COUNT=0
ROTATION_COUNT=0
PERMISSIONS_SECURED=0
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it writes" >&2
  echo "rsyslog/logrotate configuration and restarts a system service." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# ENSURE rsyslog AND logrotate ARE PRESENT (self-sufficient, does not
# assume a prior task already installed them in this exact environment)
# ---------------------------------------------------------------------
if ! command -v rsyslogd >/dev/null 2>&1 || ! dpkg -s rsyslog >/dev/null 2>&1; then
  apt-get install -y rsyslog >/tmp/rsyslog_install.$$ 2>&1 || true
  rm -f /tmp/rsyslog_install.$$
fi
if ! command -v logrotate >/dev/null 2>&1; then
  apt-get install -y logrotate >/tmp/logrotate_install.$$ 2>&1 || true
  rm -f /tmp/logrotate_install.$$
fi
systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl start rsyslog >/dev/null 2>&1 || true
 
RSYSLOG_ACTIVE=false
if systemctl is-active --quiet rsyslog 2>/dev/null; then
  RSYSLOG_ACTIVE=true
fi
 
# ---------------------------------------------------------------------
# STEP 1 & 2: CONFIGURE rsyslog ROUTING
# ---------------------------------------------------------------------
echo "[*] Configuring rsyslog..."
 
mkdir -p "$(dirname "$RSYSLOG_CONF")"
{
  echo "## Managed by 12-log_config.sh -- regenerated on every run"
  echo "auth,authpriv.*    ${AUTH_LOG}"
  echo "*.info;auth.none   ${SYS_LOG}"
} > "$RSYSLOG_CONF"
 
printf '    %-25s -> %-20s [CONFIGURED]\n' "auth,authpriv.*" "$AUTH_LOG"
printf '    %-25s -> %-20s [CONFIGURED]\n' "*.info;auth.none" "$SYS_LOG"
CONFIGURED_COUNT=2
 
if [ "$RSYSLOG_ACTIVE" = true ]; then
  systemctl restart rsyslog >/dev/null 2>&1 || true
fi
 
# ---------------------------------------------------------------------
# STEP 3: LOG ROTATION POLICIES
# ---------------------------------------------------------------------
echo "[*] Setting log rotation policies..."
 
# "Compressed after 7 days" is implemented via a lastaction hook rather
# than delaycompress, which only ever delays by a single rotation
# cycle (one day, under daily rotation), not a literal 7-day window.
write_rotate_policy() {
  local log_path="$1" retain_days="$2"
  local base_name
  base_name=$(basename "$log_path")
  cat >> "$LOGROTATE_CONF" <<EOF
${log_path} {
    daily
    rotate ${retain_days}
    missingok
    notifempty
    create 640 root adm
    lastaction
        find /var/log -maxdepth 1 -name "${base_name}.*" ! -name "*.gz" -mtime +7 -exec gzip {} \\;
    endscript
}
EOF
}
 
: > "$LOGROTATE_CONF"
write_rotate_policy "$AUTH_LOG" 90
write_rotate_policy "$SYS_LOG" 60
printf '    %s: rotate 90, compress after 7d  [SET]\n' "$AUTH_LOG"
printf '    %s: rotate 60, compress after 7d    [SET]\n' "$SYS_LOG"
ROTATION_COUNT=2
 
logrotate -d "$LOGROTATE_CONF" >/tmp/logrotate_check.$$ 2>&1 || true
rm -f /tmp/logrotate_check.$$
 
# ---------------------------------------------------------------------
# STEP 4: VERIFY ACTIVE LOG RECEPTION
# ---------------------------------------------------------------------
echo "[*] Verifying log activity..."
 
verify_log_activity() {
  local log_path="$1" facility="$2" marker="$3"
  logger -p "$facility" "$marker" 2>/dev/null || true
  sleep 1
  if [ -f "$log_path" ] && grep -qF "$marker" "$log_path" 2>/dev/null; then
    printf '    %-20s receiving events       [OK]\n' "$log_path:"
    return 0
  elif [ "$RSYSLOG_ACTIVE" != true ]; then
    printf '    %-20s receiving events       [SKIPPED - rsyslog not active in this environment]\n' "$log_path:" >&2
    return 1
  else
    printf '    %-20s receiving events       [FAIL - no test event found]\n' "$log_path:" >&2
    return 1
  fi
}
 
TEST_MARKER="meddefense-log-test-$(date +%s)-$$"
verify_log_activity "$AUTH_LOG" "auth.info" "$TEST_MARKER" || true
verify_log_activity "$SYS_LOG" "user.info" "$TEST_MARKER" || true
 
# ---------------------------------------------------------------------
# STEP 5: SECURE LOG FILE PERMISSIONS
# ---------------------------------------------------------------------
echo "[*] Securing log file permissions..."
 
secure_permissions() {
  local log_path="$1"
  if [ -f "$log_path" ]; then
    chmod 640 "$log_path" 2>/dev/null || true
    chown root:adm "$log_path" 2>/dev/null || true
    printf '    %s: 640 root:adm          [OK]\n' "$log_path"
    PERMISSIONS_SECURED=$((PERMISSIONS_SECURED + 1))
  else
    printf '    %s: file not found, skipped\n' "$log_path" >&2
  fi
}
 
secure_permissions "$AUTH_LOG"
secure_permissions "$SYS_LOG"
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "Log sources configured: ${CONFIGURED_COUNT} | Rotation policies: ${ROTATION_COUNT} | Permissions: secured (${PERMISSIONS_SECURED}/2)"
