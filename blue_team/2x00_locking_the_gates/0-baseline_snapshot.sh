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

set -uo pipefail

OUTPUT_DIR="./baseline_output"
JSON_OUTPUT="${OUTPUT_DIR}/0-baseline_snapshot.json"
mkdir -p "${OUTPUT_DIR}"

if [ "$(id -u)" -ne 0 ]; then
  echo "WARNING: not running as root (sudo). Some results will be incomplete." >&2
fi

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

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

HOSTNAME_VAL=$(hostname)
OS_NAME=$(grep -oP '(?<=^PRETTY_NAME=").*(?="$)' /etc/os-release 2>/dev/null || echo "unknown")
KERNEL_VERSION=$(uname -r)
UPTIME_VAL=$(uptime -p 2>/dev/null || echo "unknown")
SNAPSHOT_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if command -v systemctl >/dev/null 2>&1; then
  SERVICES_LIST=$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')
else
  SERVICES_LIST=""
fi
SERVICES_COUNT=$(printf '%s\n' "$SERVICES_LIST" | grep -c . || true)

if command -v ss >/dev/null 2>&1; then
  PORTS_LIST=$(ss -tulnH 2>/dev/null)
else
  PORTS_LIST=$(netstat -tuln 2>/dev/null | tail -n +3 || echo "")
fi
PORTS_COUNT=$(printf '%s\n' "$PORTS_LIST" | grep -c . || true)

SUID_LIST=$(find / -xdev -type f -perm -4000 2>/dev/null)
SUID_COUNT=$(printf '%s\n' "$SUID_LIST" | grep -c . || true)
SGID_LIST=$(find / -xdev -type f -perm -2000 2>/dev/null)
SGID_COUNT=$(printf '%s\n' "$SGID_LIST" | grep -c . || true)

WORLD_WRITABLE_LIST=$(find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -0002 -print 2>/dev/null)
WORLD_WRITABLE_COUNT=$(printf '%s\n' "$WORLD_WRITABLE_LIST" | grep -c . || true)

SYSCTL_PARAMS="net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.ip_forward net.ipv4.icmp_echo_ignore_broadcasts kernel.randomize_va_space fs.suid_dumpable"
SYSCTL_JSON="{"
first=true
for param in $SYSCTL_PARAMS; do
  value=$(sysctl -n "$param" 2>/dev/null || echo "unavailable")
  if [ "$first" = true ]; then first=false; else SYSCTL_JSON+=","; fi
  SYSCTL_JSON+="\"${param}\":\"$(json_escape "$value")\""
done
SYSCTL_JSON+="}"

SSH_DIRECTIVES="permitrootlogin passwordauthentication pubkeyauthentication protocol x11forwarding maxauthtries clientaliveinterval allowusers"
if command -v sshd >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
  SSH_EFFECTIVE=$(sshd -T 2>/dev/null)
else
  SSH_EFFECTIVE=""
fi
SSH_JSON="{"
first=true
for directive in $SSH_DIRECTIVES; do
  value=$(printf '%s\n' "$SSH_EFFECTIVE" | grep -i "^${directive} " | awk '{$1=""; print $0}' | sed 's/^ //')
  [ -z "$value" ] && value="not-set"
  if [ "$first" = true ]; then first=false; else SSH_JSON+=","; fi
  SSH_JSON+="\"${directive}\":\"$(json_escape "$value")\""
done
SSH_JSON+="}"

USER_ACCOUNTS=$(awk -F: '$3>=1000 && $1!="nobody" {print $1}' /etc/passwd)
SUDO_MEMBERS=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n')

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

echo "Hostname: ${HOSTNAME_VAL}"
echo "OS: ${OS_NAME}"
echo "Running services: ${SERVICES_COUNT}"
echo "Open ports: ${PORTS_COUNT}"
echo "SUID binaries: ${SUID_COUNT}"
echo "SGID binaries: ${SGID_COUNT}"
echo "World-writable files: ${WORLD_WRITABLE_COUNT}"
echo ""
echo "Full structured baseline written to: ${JSON_OUTPUT}"
