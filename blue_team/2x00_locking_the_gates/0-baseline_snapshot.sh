#!/bin/bash
#
# 0-baseline_snapshot.sh
#
# Goal: capture the complete, unmodified security baseline of a Linux system
# before any hardening action is taken. This is the "before" half of the
# before/after delta every later task in this project will be measured
# against (Specific Project Rule: "Show the delta").
#
# This script makes NO changes to the system. It only reads and records.
# Because it is read-only, idempotency here means something specific:
# running it twice must produce the same structured output file, cleanly
# overwritten each time, not two different files piling up.
#
# MedDefense context: this baseline is what proves, later, that
# billing-srv-01's Lynis hardening index actually moved from the low 50s
# to above 80, that SSH actually stopped accepting password auth
# (1x02 Finding 009), and that the kernel hardening addressed the class of
# weakness behind Finding 026 (47 known kernel CVEs on the old, unpatched
# kernel). Without this file, none of that is provable, only claimed.
 
set -euo pipefail
 
# ---------------------------------------------------------------------
# SETUP
# ---------------------------------------------------------------------
# Where we write our output. A fixed filename (not timestamped) is a
# deliberate idempotency choice: re-running this script always produces
# THE current baseline file, not an ever-growing pile of dated snapshots.
OUTPUT_DIR="./baseline_output"
JSON_OUTPUT="${OUTPUT_DIR}/0-baseline_snapshot.json"
mkdir -p "${OUTPUT_DIR}"
 
# A gentle, non-fatal warning if not run as root: several of the checks
# below (full-filesystem SUID search, sshd -T, some sysctl reads) are
# far less complete without root privileges. We warn instead of exiting,
# so the script still runs for a partial check if that is genuinely
# what the operator wants.
if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: not running as root (sudo). Some results (SUID scan," >&2
  echo "world-writable scan, SSH effective config) will be incomplete." >&2
fi
 
# ---------------------------------------------------------------------
# JSON HELPERS
# ---------------------------------------------------------------------
# Escapes a string so it is safe to place inside a JSON double-quoted
# value: backslashes first (order matters), then quotes, then newlines.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}
 
# Turns a multi-line string (one item per line) into a JSON array of
# strings, e.g. "a\nb\nc" becomes ["a","b","c"]. Blank lines are skipped.
json_array_from_lines() {
  local lines="$1"
  local first=true
  printf '['
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if [ "$first" = true ]; then first=false; else printf ','; fi
    printf '"%s"' "$(json_escape "$line")"
  done <<< "$lines"
  printf ']'
}
 
# ---------------------------------------------------------------------
# 1. SYSTEM IDENTIFICATION
# ---------------------------------------------------------------------
HOSTNAME_VAL=$(hostname)
OS_NAME=$(grep -oP '(?<=^PRETTY_NAME=").*(?="$)' /etc/os-release 2>/dev/null || echo "unknown")
KERNEL_VERSION=$(uname -r)
UPTIME_VAL=$(uptime -p 2>/dev/null || echo "unknown")
SNAPSHOT_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
 
# ---------------------------------------------------------------------
# 2. RUNNING SERVICES
# ---------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  SERVICES_LIST=$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}' || true)
else
  SERVICES_LIST=""
fi
SERVICES_COUNT=$(printf '%s\n' "$SERVICES_LIST" | grep -c . || true)
 
# ---------------------------------------------------------------------
# 3. OPEN PORTS / LISTENING SOCKETS
# ---------------------------------------------------------------------
# -t tcp, -u udp, -l listening only, -n numeric (no slow DNS/service
# name lookups), -H no header line to keep the output easy to count.
if command -v ss >/dev/null 2>&1; then
  PORTS_LIST=$(ss -tulnH 2>/dev/null || true)
else
  PORTS_LIST=$(netstat -tuln 2>/dev/null | tail -n +3 || echo "")
fi
PORTS_COUNT=$(printf '%s\n' "$PORTS_LIST" | grep -c . || true)
 
# ---------------------------------------------------------------------
# 4. SUID AND SGID BINARIES
# ---------------------------------------------------------------------
# 4000 = SUID bit, 2000 = SGID bit. 2>/dev/null suppresses the many
# "Permission denied" lines find produces when it hits directories the
# current user cannot read; those are expected noise, not real errors.
SUID_LIST=$(find / -xdev -type f -perm -4000 2>/dev/null || true)
SUID_COUNT=$(printf '%s\n' "$SUID_LIST" | grep -c . || true)
SGID_LIST=$(find / -xdev -type f -perm -2000 2>/dev/null || true)
SGID_COUNT=$(printf '%s\n' "$SGID_LIST" | grep -c . || true)
 
# ---------------------------------------------------------------------
# 5. WORLD-WRITABLE FILES (excluding /proc, /sys, /dev per the task)
# ---------------------------------------------------------------------
# -prune stops find from descending into the excluded paths at all,
# rather than merely filtering their results afterward (much faster
# and avoids permission noise from virtual filesystems).
WORLD_WRITABLE_LIST=$(find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -0002 -print 2>/dev/null || true)
WORLD_WRITABLE_COUNT=$(printf '%s\n' "$WORLD_WRITABLE_LIST" | grep -c . || true)
 
# ---------------------------------------------------------------------
# 6. SECURITY-RELEVANT SYSCTL PARAMETERS
# ---------------------------------------------------------------------
# These specific parameters are the ones this project's own kernel
# hardening task (a later script) will change. Recording them now,
# unmodified, is what proves that later change actually happened.
SYSCTL_PARAMS="net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.ip_forward net.ipv4.icmp_echo_ignore_broadcasts kernel.randomize_va_space fs.suid_dumpable"
SYSCTL_JSON="{"
first=true
for param in $SYSCTL_PARAMS; do
  value=$(sysctl -n "$param" 2>/dev/null || echo "unavailable")
  if [ "$first" = true ]; then first=false; else SYSCTL_JSON+=","; fi
  SYSCTL_JSON+="\"${param}\":\"$(json_escape "$value")\""
done
SYSCTL_JSON+="}"
 
# ---------------------------------------------------------------------
# 7. SSH CONFIGURATION
# ---------------------------------------------------------------------
# sshd -T prints the EFFECTIVE configuration (explicit settings merged
# with Ubuntu's own defaults for anything not explicitly set), which is
# more accurate than grepping sshd_config directly: a setting absent
# from the file still has a real, active default value that matters.
SSH_DIRECTIVES="permitrootlogin passwordauthentication pubkeyauthentication protocol x11forwarding maxauthtries clientaliveinterval allowusers"
if command -v sshd >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
  SSH_EFFECTIVE=$(sshd -T 2>/dev/null || true)
else
  SSH_EFFECTIVE=""
fi
SSH_JSON="{"
first=true
for directive in $SSH_DIRECTIVES; do
  value=$(printf '%s\n' "$SSH_EFFECTIVE" | grep -i "^${directive} " | awk '{$1=""; print $0}' | sed 's/^ //' || true)
  [ -z "$value" ] && value="not-set"
  if [ "$first" = true ]; then first=false; else SSH_JSON+=","; fi
  SSH_JSON+="\"${directive}\":\"$(json_escape "$value")\""
done
SSH_JSON+="}"
 
# ---------------------------------------------------------------------
# 8. USER ACCOUNTS AND SUDO GROUP MEMBERSHIP
# ---------------------------------------------------------------------
# UID >= 1000 is the standard Ubuntu convention for "real" human user
# accounts, as opposed to system/service accounts (UID < 1000).
USER_ACCOUNTS=$(awk -F: '$3>=1000 && $1!="nobody" {print $1}' /etc/passwd)
SUDO_MEMBERS=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' || true)
 
# ---------------------------------------------------------------------
# BUILD FINAL JSON OUTPUT
# ---------------------------------------------------------------------
cat > "$JSON_OUTPUT" <<JSON_EOF
{
  "snapshot_date": "${SNAPSHOT_DATE}",
  "system_identification": {
    "hostname": "$(json_escape "$HOSTNAME_VAL")",
    "os": "$(json_escape "$OS_NAME")",
    "kernel_version": "$(json_escape "$KERNEL_VERSION")",
    "uptime": "$(json_escape "$UPTIME_VAL")"
  },
  "running_services": {
    "count": ${SERVICES_COUNT},
    "list": $(json_array_from_lines "$SERVICES_LIST")
  },
  "open_ports": {
    "count": ${PORTS_COUNT},
    "list": $(json_array_from_lines "$PORTS_LIST")
  },
  "suid_binaries": {
    "count": ${SUID_COUNT},
    "list": $(json_array_from_lines "$SUID_LIST")
  },
  "sgid_binaries": {
    "count": ${SGID_COUNT},
    "list": $(json_array_from_lines "$SGID_LIST")
  },
  "world_writable_files": {
    "count": ${WORLD_WRITABLE_COUNT},
    "list": $(json_array_from_lines "$WORLD_WRITABLE_LIST")
  },
  "sysctl_parameters": ${SYSCTL_JSON},
  "ssh_configuration": ${SSH_JSON},
  "user_accounts": {
    "real_users": $(json_array_from_lines "$USER_ACCOUNTS"),
    "sudo_group_members": $(json_array_from_lines "$SUDO_MEMBERS")
  }
}
JSON_EOF
 
# ---------------------------------------------------------------------
# HUMAN-READABLE SUMMARY (matches the task's expected output format)
# ---------------------------------------------------------------------
echo "Hostname: ${HOSTNAME_VAL}"
echo "OS: ${OS_NAME}"
echo "Running services: ${SERVICES_COUNT}"
echo "Open ports: ${PORTS_COUNT}"
echo "SUID binaries: ${SUID_COUNT}"
echo "SGID binaries: ${SGID_COUNT}"
echo "World-writable files: ${WORLD_WRITABLE_COUNT}"
echo ""
echo "Full structured baseline written to: ${JSON_OUTPUT}"
