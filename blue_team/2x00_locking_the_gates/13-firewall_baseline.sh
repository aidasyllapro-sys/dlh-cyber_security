#!/bin/bash
#
# 13-firewall_baseline.sh
#
# Configures UFW: default-deny inbound, default-allow outbound, allow
# rules for SSH/HTTP/HTTPS/MySQL only, logging for denied connections.
#
# NETWORK SUBSTITUTION, disclosed directly: the task's own text uses
# illustrative addresses (10.10.1.0/24 management, 10.10.2.0/24 app
# network) from MedDefense's original fictional network plan. This
# lab's real, confirmed network is 192.168.74.0/24 (the only network
# Kali and billing-srv-01 actually share), and billing-srv-01 runs
# Apache and MySQL on the same host, not on separate app/db servers.
# Using the task's literal fictional CIDR would guarantee this host
# rejects the operator's own real connection the moment the firewall
# activates. Both restricted rules below therefore use the real,
# confirmed 192.168.74.0/24 network instead.
#
# LOCKOUT-SAFETY DESIGN, disclosed directly: enabling a default-deny
# firewall is the single highest-risk action in this entire project;
# unlike SSH/PAM changes, a network-layer lockout has no application-
# level recovery path at all, only local console access. Before
# enabling, this script checks the CURRENT SSH client's real source
# IP (from $SSH_CLIENT) against the allow-list and refuses to proceed
# if it would not be allowed. It then schedules an automatic
# `ufw disable` a few minutes later via `at`, cancelled only if the
# operator explicitly confirms connectivity survived, so a mistake
# self-heals instead of requiring console/hypervisor recovery.
 
set -euo pipefail
 
MGMT_NETWORK="192.168.74.0/24"
SAFETY_WINDOW_MINUTES=5
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it" >&2
  echo "configures the host firewall." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# ENSURE ufw IS PRESENT (self-sufficient, matching this project's
# other hardening scripts)
# ---------------------------------------------------------------------
if ! command -v ufw >/dev/null 2>&1; then
  apt-get install -y ufw >/tmp/ufw_install.$$ 2>&1 || true
  rm -f /tmp/ufw_install.$$
fi
if ! command -v ufw >/dev/null 2>&1; then
  echo "ERROR: ufw could not be installed. Aborting without making any" >&2
  echo "firewall changes." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# LOCKOUT PRE-FLIGHT CHECK: refuse to proceed if the operator's own
# current SSH session would not survive the new default-deny policy.
# ---------------------------------------------------------------------
if [ -n "${SSH_CLIENT:-}" ]; then
  CLIENT_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
  CLIENT_IN_RANGE=$(python3 -c "
import ipaddress, sys
try:
    ip = ipaddress.ip_address('${CLIENT_IP}')
    net = ipaddress.ip_network('${MGMT_NETWORK}')
    print('yes' if ip in net else 'no')
except Exception:
    print('unknown')
" 2>/dev/null || echo "unknown")
 
  if [ "$CLIENT_IN_RANGE" = "no" ]; then
    echo "ERROR: your current SSH connection is from ${CLIENT_IP}, which" >&2
    echo "is NOT inside the allowed management network ${MGMT_NETWORK}." >&2
    echo "Enabling this firewall would lock out your own session with no" >&2
    echo "network-based recovery path. Aborting without making any" >&2
    echo "changes. Connect from within ${MGMT_NETWORK} or adjust" >&2
    echo "MGMT_NETWORK in this script, then re-run." >&2
    exit 1
  fi
fi
 
# ---------------------------------------------------------------------
# STEP 1: DEFAULT POLICIES
# ---------------------------------------------------------------------
echo "[*] Configuring UFW..."
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
echo "    Default incoming: deny"
echo "    Default outgoing: allow"
 
# ---------------------------------------------------------------------
# STEP 2: ALLOW RULES FOR REQUIRED SERVICES ONLY
# ---------------------------------------------------------------------
echo "[*] Adding allow rules..."
 
ufw allow from "$MGMT_NETWORK" to any port 22 proto tcp >/dev/null 2>&1
printf '    %-25s [ADDED] SSH - management only\n' "22/tcp from ${MGMT_NETWORK}"
 
ufw allow 80/tcp >/dev/null 2>&1
printf '    %-25s [ADDED] HTTP\n' "80/tcp"
 
ufw allow 443/tcp >/dev/null 2>&1
printf '    %-25s [ADDED] HTTPS\n' "443/tcp"
 
ufw allow from "$MGMT_NETWORK" to any port 3306 proto tcp >/dev/null 2>&1
printf '    %-25s [ADDED] MySQL - app network only\n' "3306/tcp from ${MGMT_NETWORK}"
 
RULE_COUNT=4
 
# ---------------------------------------------------------------------
# STEP 3: LOGGING FOR DENIED CONNECTIONS
# ---------------------------------------------------------------------
echo "[*] Enabling logging..."
ufw logging low >/dev/null 2>&1
echo "    Logging: on (low)"
 
# ---------------------------------------------------------------------
# ACTIVATE, WITH THE SCHEDULED SAFETY-NET DISABLE
# ---------------------------------------------------------------------
echo "[*] Activating firewall..."
echo "y" | ufw enable >/dev/null 2>&1 || true
 
if systemctl is-active --quiet atd 2>/dev/null || command -v at >/dev/null 2>&1; then
  systemctl start atd >/dev/null 2>&1 || true
  echo "ufw disable" | at now + "${SAFETY_WINDOW_MINUTES}" minutes >/tmp/at_out.$$ 2>&1 || true
  SAFETY_JOB=$(grep -oE 'job [0-9]+' /tmp/at_out.$$ | awk '{print $2}' || true)
  rm -f /tmp/at_out.$$
  if [ -n "${SAFETY_JOB:-}" ]; then
    echo "    Safety net: firewall auto-disables in ${SAFETY_WINDOW_MINUTES} min" >&2
    echo "    unless you cancel it. Verify your SSH access NOW, then run:" >&2
    echo "    atrm ${SAFETY_JOB}" >&2
  fi
else
  echo "    WARNING: 'at' not available, no scheduled safety-net disable" >&2
  echo "    was set. Verify SSH access from a SEPARATE session before" >&2
  echo "    closing this one." >&2
fi
 
UFW_STATUS=$(ufw status | head -1 | awk '{print $2}')
echo "    UFW: ${UFW_STATUS:-unknown}"
echo "Rules: ${RULE_COUNT} allow, default deny"
