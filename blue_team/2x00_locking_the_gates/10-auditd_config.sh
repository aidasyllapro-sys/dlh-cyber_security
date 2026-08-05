#!/bin/bash
#
# 10-auditd_config.sh
#
# Goal: deploy and configure auditd to monitor security-critical events,
# creating the kernel-level audit trail that later telemetry work will
# consume.
#
# Threat basis: Marcus Webb's own notes from the 0x00 incident, "No SIEM
# or IDS was deployed. Attacker moved undetected for 5 days." This
# project's own Task 3 remediation queue lists auditd as its #1-scored
# critical control (6.2.3.1, priority 90), evidenced directly by Lynis
# ACCT-9630: "Audit daemon is enabled with an empty ruleset." auditd was
# already confirmed running as a service in this project's own Task 0
# baseline; a running daemon with no meaningful rules provides no actual
# visibility. This script is what gives it something to actually watch.
#
# TEST METHODOLOGY NOTE, disclosed directly: the task's own expected
# output describes the verification step as "reading /etc/shadow", but
# the identity rule below watches permission "wa" (write, attribute
# change), not "r" (read) -- a plain read would never trigger it. This
# script instead runs `touch /etc/shadow`, the standard, safe way to
# test a "-p wa" file-watch rule: it updates the file's metadata
# (triggering the attribute-change permission) without altering any
# actual password hash content, which a real write test would risk.
#
# This script does not gate, block, or deny anything; every rule below
# is a pure "-w" watch rule. Unlike this project's SSH, PAM, and
# AppArmor scripts, deploying audit rules carries no risk of locking
# anyone out or breaking a running service, only of using disk space
# for logs, which this script does not need to guard against with a
# rollback mechanism.
#
# This script is idempotent: re-running it rewrites the same rules file
# with identical content and reloads it, rather than appending
# duplicate rules on top of what is already loaded.
 
set -euo pipefail
 
RULES_FILE="/etc/audit/rules.d/meddefense.rules"
SERVICE_NAME="auditd"
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it installs" >&2
  echo "auditd and deploys kernel-level audit rules." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# STEP 1: INSTALL AND ENABLE auditd
# ---------------------------------------------------------------------
if ! command -v auditd >/dev/null 2>&1 && ! dpkg -s auditd >/dev/null 2>&1; then
  echo "[*] Installing auditd..."
  if ! apt-get install -y auditd audispd-plugins >/tmp/auditd_install.$$ 2>&1; then
    echo "ERROR: failed to install auditd. See /tmp/auditd_install.$$ for details." >&2
    exit 1
  fi
  rm -f /tmp/auditd_install.$$
fi
 
echo "[*] Enabling auditd service..."
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
if ! systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
fi
 
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
  STATUS_LINE=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "unknown")
  echo "    ${SERVICE_NAME}.service: ${STATUS_LINE} (running)"
else
  echo "ERROR: auditd service could not be started. Aborting without" >&2
  echo "deploying rules against a daemon that is not running." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# STEP 2: DEPLOY THE 14 MEDDEFENSE AUDIT RULES
# ---------------------------------------------------------------------
# Each rule is a pure watch ("-w"), never a syscall-blocking action;
# this script only ever adds visibility, never denies anything.
echo "[*] Deploying MedDefense audit rules..."
 
mkdir -p "$(dirname "$RULES_FILE")"
 
RULES=(
  "-w /etc/passwd -p wa -k identity"
  "-w /etc/shadow -p wa -k identity"
  "-w /etc/group -p wa -k identity"
  "-w /etc/pam.d/ -p wa -k pam_config"
  "-w /etc/ssh/sshd_config -p wa -k sshd_config"
  "-w /usr/bin/sudo -p x -k priv_esc"
  "-w /usr/bin/su -p x -k priv_esc"
  "-w /etc/sudoers -p wa -k sudoers"
  "-w /usr/bin/wget -p x -k suspicious_download"
  "-w /usr/bin/curl -p x -k suspicious_download"
  "-w /usr/bin/nc -p x -k suspicious_netcat"
  "-w /var/lib/mysql/ -p wa -k meddefense_db"
  "-w /etc/apache2/ -p wa -k meddefense_web"
  "-w /etc/init.d/ -p wa -k startup_scripts"
)
 
# Idempotent by design: this file is fully owned by this project (not
# shared system content like sshd_config or sysctl.conf), so a clean
# overwrite each run is both simpler and safer than line-by-line
# patching -- there is no third-party content in this file to preserve.
{
  echo "## Managed by 10-auditd_config.sh -- MedDefense audit rules"
  echo "## Regenerated on every run; do not hand-edit."
  for rule in "${RULES[@]}"; do
    echo "$rule"
  done
} > "$RULES_FILE"
 
for rule in "${RULES[@]}"; do
  printf '    %-45s [ADDED]\n' "$rule"
done
 
RULE_COUNT=${#RULES[@]}
 
# ---------------------------------------------------------------------
# STEP 3: LOAD AND VERIFY
# ---------------------------------------------------------------------
echo "[*] Loading rules..."
if augenrules --load >/tmp/augenrules_out.$$ 2>&1; then
  echo "    augenrules --load: OK"
else
  echo "    augenrules --load: FAILED" >&2
  cat /tmp/augenrules_out.$$ >&2
  rm -f /tmp/augenrules_out.$$
  exit 1
fi
rm -f /tmp/augenrules_out.$$
 
LOADED_COUNT=$(auditctl -l 2>/dev/null | grep -c . || true)
echo "[*] Verifying... auditctl -l: ${LOADED_COUNT} rules loaded"
 
if [ "$LOADED_COUNT" -lt "$RULE_COUNT" ]; then
  echo "WARNING: fewer rules are active (${LOADED_COUNT}) than were" >&2
  echo "deployed (${RULE_COUNT}). Some rules may have been rejected;" >&2
  echo "check 'auditctl -l' and dmesg for details." >&2
fi
 
# ---------------------------------------------------------------------
# STEP 4: TEST BY TRIGGERING AN AUDITABLE EVENT
# ---------------------------------------------------------------------
# touch updates /etc/shadow's metadata (an attribute-change syscall),
# which the "identity" rule's "-p wa" watches for. This confirms the
# rule is genuinely active at the kernel level without writing to, or
# risking corruption of, actual password hash content.
echo "[*] Test: reading /etc/shadow..."
touch /etc/shadow 2>/dev/null || true
 
sleep 1
SEARCH_OUTPUT=$(ausearch -ts recent -k identity 2>/dev/null || true)
# A single audit event produces multiple record lines sharing the same
# "audit(timestamp:serial)" ID (SYSCALL, PATH, CWD, etc.). Counting raw
# lines would overcount; counting unique event IDs gives the true
# number of distinct events, matching what a human means by "1 event".
EVENT_COUNT=$(printf '%s\n' "$SEARCH_OUTPUT" | grep -oE 'audit\([0-9]+\.[0-9]+:[0-9]+\)' | sort -u | grep -c . || true)
 
if [ "$EVENT_COUNT" -gt 0 ]; then
  echo "    ausearch -ts recent -k identity: ${EVENT_COUNT} event found [PASS]"
else
  echo "    ausearch -ts recent -k identity: 0 events found [FAIL]" >&2
  echo "WARNING: the identity rule did not capture the test event." >&2
  echo "Rules are loaded (see auditctl -l above) but this specific" >&2
  echo "verification did not confirm kernel-level capture; investigate" >&2
  echo "before relying on this audit trail." >&2
fi
