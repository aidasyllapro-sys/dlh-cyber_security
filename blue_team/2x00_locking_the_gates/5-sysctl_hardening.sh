#!/bin/bash
#
# 5-sysctl_hardening.sh
#
# Goal: harden the Linux kernel network stack and memory protections via
# sysctl, so a compromised billing-srv-01, web-srv-01, or log-srv-01
# cannot become a routing pivot or a trivially exploitable memory-safety
# target for an attacker already inside the network.
#
# Threat basis: Crimson Tide Phase 3 (lateral movement across a flat
# network). A compromised host with IP forwarding enabled becomes a
# router for the attacker; accepted ICMP redirects let an attacker
# reroute traffic; disabled ASLR makes memory-corruption exploits
# reliable rather than probabilistic. This project's own Task 0
# baseline already confirmed several of these are NOT currently
# hardened on billing-srv-01 (ip_forward=1, fs.suid_dumpable=2), and
# Task 3's remediation queue lists these among its highest-priority,
# fully evidence-confirmed items (controls 1.5.3 and 3.3.1.1).
#
# This script makes changes to a live kernel's runtime parameters and
# to /etc/sysctl.conf. It is idempotent: running it twice reapplies
# the same 14 parameters to the same final state, appends nothing
# twice, and reports the same PASS results both times.
 
set -euo pipefail
 
SYSCTL_CONF="/etc/sysctl.conf"
BACKUP_PATH="/etc/sysctl.conf.bak"
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it writes" >&2
  echo "${SYSCTL_CONF} and live kernel parameters under /proc/sys." >&2
  exit 1
fi
 
if [ ! -f "$SYSCTL_CONF" ]; then
  echo "ERROR: ${SYSCTL_CONF} not found." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# STEP 1: BACKUP
# ---------------------------------------------------------------------
echo "[*] Backing up ${SYSCTL_CONF}"
cp -p "$SYSCTL_CONF" "$BACKUP_PATH" || {
  echo "ERROR: backup command failed, aborting before making any changes." >&2
  exit 1
}
if [ ! -f "$BACKUP_PATH" ]; then
  echo "ERROR: backup failed, aborting before making any changes." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# THE 14 HARDENING PARAMETERS
# ---------------------------------------------------------------------
# Parallel arrays: KEY[i] is the dotted sysctl name, VALUE[i] is the
# hardened value it must be set to. This is the single source of truth
# for applying, backfilling sysctl.conf, and verifying, so the applied
# set and the verified set can never drift out of sync with each other.
KEY=()
VALUE=()
 
add_param() { KEY+=("$1"); VALUE+=("$2"); }
 
# Network stack hardening: prevents a compromised host from acting as
# a router or having its traffic silently redirected (Crimson Tide
# Phase 3 flat-network lateral movement pattern).
add_param "net.ipv4.ip_forward" "0"
add_param "net.ipv4.conf.all.accept_redirects" "0"
add_param "net.ipv4.conf.default.accept_redirects" "0"
add_param "net.ipv4.conf.all.send_redirects" "0"
add_param "net.ipv4.conf.all.accept_source_route" "0"
add_param "net.ipv4.conf.all.log_martians" "1"
add_param "net.ipv4.tcp_syncookies" "1"
add_param "net.ipv4.icmp_echo_ignore_broadcasts" "1"
 
# IPv6 disabling: none of these three servers' documented operations
# use IPv6; disabling it removes an entire, unused, unmonitored
# protocol stack as an avenue of attack.
add_param "net.ipv6.conf.all.disable_ipv6" "1"
add_param "net.ipv6.conf.default.disable_ipv6" "1"
 
# Memory protection: ASLR (2 = full randomization) makes memory
# corruption exploits probabilistic rather than reliable; disabling
# SUID core dumps (already confirmed at the least-restrictive value,
# 2, in this project's own Task 0 baseline) prevents credential or
# session data resident in memory from being written to disk on crash.
add_param "kernel.randomize_va_space" "2"
add_param "fs.suid_dumpable" "0"
 
# Kernel information disclosure hardening: restricts dmesg and kernel
# pointer exposure, which otherwise can leak addresses useful for
# defeating ASLR itself or for post-exploitation reconnaissance.
add_param "kernel.dmesg_restrict" "1"
add_param "kernel.kptr_restrict" "2"
 
PARAM_COUNT=${#KEY[@]}
 
# ---------------------------------------------------------------------
# STEP 2: IDEMPOTENT sysctl.conf UPDATE
# ---------------------------------------------------------------------
# Same pattern as this project's SSH hardening script: replace an
# existing active line, un-comment and replace a commented default, or
# append if neither exists. sysctl.conf uses "key = value" syntax.
set_sysctl_conf_line() {
  local key="$1"
  local value="$2"
  local line="${key} = ${value}"
  if grep -qE "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$SYSCTL_CONF"; then
    sed -i -E "s|^[[:space:]]*${key//./\\.}[[:space:]]*=.*|${line}|" "$SYSCTL_CONF"
  elif grep -qE "^[[:space:]]*#[[:space:]]*${key//./\\.}[[:space:]]*=" "$SYSCTL_CONF"; then
    sed -i -E "s|^[[:space:]]*#[[:space:]]*${key//./\\.}[[:space:]]*=.*|${line}|" "$SYSCTL_CONF"
  else
    echo "$line" >> "$SYSCTL_CONF"
  fi
}
 
echo "[*] Applying kernel hardening parameters..."
for i in "${!KEY[@]}"; do
  set_sysctl_conf_line "${KEY[$i]}" "${VALUE[$i]}"
done
 
# ---------------------------------------------------------------------
# STEP 3: APPLY IMMEDIATELY
# ---------------------------------------------------------------------
sysctl -p "$SYSCTL_CONF" >/tmp/sysctl_apply_out.$$ 2>&1 || true
# sysctl -p prints each applied "key = value" line on success and a
# warning line (not a hard failure) for any parameter the running
# kernel does not expose (e.g. IPv6 support compiled out); those
# warnings do not abort this script; per-parameter verification below
# is what actually determines PASS/FAIL, not sysctl -p's own exit code.
rm -f /tmp/sysctl_apply_out.$$
 
# ---------------------------------------------------------------------
# STEP 4 & 5: VERIFY AGAINST /proc/sys AND PRINT PASS/FAIL
# ---------------------------------------------------------------------
# Compute the column width once, from the longest "key = value" string,
# so the [PASS]/[FAIL] tags line up regardless of which parameters are
# in the list above.
MAXLEN=0
for i in "${!KEY[@]}"; do
  line="${KEY[$i]} = ${VALUE[$i]}"
  if [ "${#line}" -gt "$MAXLEN" ]; then
    MAXLEN="${#line}"
  fi
done
 
PASS_COUNT=0
FAIL_COUNT=0
for i in "${!KEY[@]}"; do
  key="${KEY[$i]}"
  expected="${VALUE[$i]}"
  proc_path="/proc/sys/${key//./\/}"
  line="${key} = ${expected}"
 
  if [ -r "$proc_path" ]; then
    actual="$(cat "$proc_path" 2>/dev/null | tr -d '[:space:]')"
  else
    actual="__missing__"
  fi
 
  if [ "$actual" = "$expected" ]; then
    result="PASS"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    result="FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
 
  printf '%-*s [%s]\n' "$MAXLEN" "$line" "$result"
done
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "Parameters applied: ${PARAM_COUNT}"
echo "Verified PASS: ${PASS_COUNT}"
echo "Verified FAIL: ${FAIL_COUNT}"
 
if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
