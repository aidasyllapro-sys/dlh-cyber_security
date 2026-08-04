#!/bin/bash
#
# 9-apparmor_config.sh
#
# Goal: deploy and enforce AppArmor mandatory access control profiles
# for network-exposed services, so that a compromised process is
# confined to only the files and directories it legitimately needs,
# rather than everything the underlying Linux user account can reach.
#
# Threat basis: the 0x00 cryptominer incident compromised billing-srv-01
# through Apache, and the compromised process had full filesystem access
# as www-data (bounded only by standard Unix permissions). AppArmor is
# the difference between "the attacker got a shell on our web server"
# and "the attacker got a shell that can only touch /var/www". This
# project's own Task 3 remediation queue flags AppArmor enforcement as
# part of the same control family as service minimization (Task 7).
#
# REALITY CHECK, disclosed directly: a stock Ubuntu 22.04 install does
# NOT ship AppArmor profiles for apache2 or mysqld by default (unlike,
# say, cups or tcpdump, which often do). "Switching complain to
# enforce" therefore only applies if a profile already exists; where
# none exists, this script writes a new, deliberately conservative
# profile covering the well-established, standard paths these daemons
# need, then enforces it. This is a best-effort, generic profile built
# from well-known AppArmor patterns for these exact daemons; it is not
# a substitute for tuning against this specific application's real,
# observed file access over time (the standard AppArmor workflow is
# complain mode first, aa-logprof to learn from real usage, then
# enforce), which is procedurally the more rigorous approach but not
# what this task calls for.
#
# SAFETY-CRITICAL DESIGN NOTE: after enforcing a profile for apache2 or
# mysqld, this script verifies the corresponding service is still
# active. If enforcement broke the service, it automatically reverts
# that specific profile to complain mode rather than leaving a broken
# production service running under a profile too strict for its real
# needs. This mirrors the same safety-first rollback judgment already
# applied throughout this project (Tasks 4, 6, 8).
#
# This script is idempotent: a profile already in enforce mode is left
# alone and reported [OK], not re-applied.
 
set -euo pipefail
# Every genuinely risky command below (aa-enforce, apparmor_parser,
# systemctl is-active) is wrapped in an if/then/else construct, which
# bash exempts from triggering set -e (a tested exit status is assumed
# deliberate). The profile_mode() helper explicitly guards its own
# internal aa-status call so a subshell failure there cannot silently
# abort the caller. This mirrors the same discipline already applied
# to this project's other hardening scripts (Tasks 0, 4, 5, 6, 7, 8).
 
APACHE_PROFILE_PATH="/etc/apparmor.d/usr.sbin.apache2"
MYSQLD_PROFILE_PATH="/etc/apparmor.d/usr.sbin.mysqld"
APACHE_BIN="/usr/sbin/apache2"
MYSQLD_BIN="/usr/sbin/mysqld"
CUSTOM_APP_PATH="/opt/meddefense/billing-app"
CUSTOM_PROFILE_PATH="/etc/apparmor.d/opt.meddefense.billing-app"
 
ENFORCE_COUNT=0
COMPLAIN_COUNT=0
UNCONFINED_COUNT=0
 
# ---------------------------------------------------------------------
# ROOT CHECK
# ---------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (sudo), since it loads" >&2
  echo "kernel-level AppArmor profiles and modifies service confinement." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# STEP 1: VERIFY APPARMOR IS INSTALLED AND RUNNING
# ---------------------------------------------------------------------
echo "[*] Checking AppArmor status..."
 
if [ -r /sys/module/apparmor/parameters/enabled ] && \
   [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ]; then
  echo "    AppArmor module: loaded"
  MODULE_LOADED=true
else
  echo "    AppArmor module: NOT LOADED"
  MODULE_LOADED=false
fi
 
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet apparmor 2>/dev/null; then
  echo "    AppArmor service: active"
  SERVICE_ACTIVE=true
else
  echo "    AppArmor service: NOT ACTIVE"
  SERVICE_ACTIVE=false
fi
 
if [ "$MODULE_LOADED" != true ] || [ "$SERVICE_ACTIVE" != true ]; then
  echo "ERROR: AppArmor is not fully active on this system. Install with" >&2
  echo "'apt install apparmor apparmor-utils' and enable the service" >&2
  echo "before running this script. Aborting without making changes." >&2
  exit 1
fi
 
if ! command -v aa-status >/dev/null 2>&1 || ! command -v aa-enforce >/dev/null 2>&1; then
  echo "ERROR: aa-status/aa-enforce not found. Install apparmor-utils." >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# JSON/TEXT-FREE STATUS LOOKUP HELPER
# ---------------------------------------------------------------------
# Returns "enforce", "complain", or "missing" for a given profile path,
# based on aa-status's own text output (the closest thing to a stable
# parse target without assuming --json support on every AppArmor
# version this might run against).
profile_mode() {
  local path="$1"
  local status_out
  status_out=$(aa-status 2>/dev/null || true)
  if printf '%s\n' "$status_out" | awk '/profiles are in enforce mode/,/^$/' | grep -qF "$path"; then
    echo "enforce"
  elif printf '%s\n' "$status_out" | awk '/profiles are in complain mode/,/^$/' | grep -qF "$path"; then
    echo "complain"
  else
    echo "missing"
  fi
}
 
# ---------------------------------------------------------------------
# STEP 2: LIST CURRENT PROFILES
# ---------------------------------------------------------------------
echo "[*] Profile enforcement:"
 
# ---------------------------------------------------------------------
# STANDARD, CONSERVATIVE PROFILE CONTENT FOR APACHE2 AND MYSQLD
# Written from well-established AppArmor patterns for these exact
# daemons. See header comment: best-effort and generic, not tuned
# against this application's real observed access.
# ---------------------------------------------------------------------
write_apache_profile() {
  cat > "$APACHE_PROFILE_PATH" <<'EOF'
#include <tunables/global>
 
/usr/sbin/apache2 {
  #include <abstractions/base>
  #include <abstractions/nameservice>
 
  capability setuid,
  capability setgid,
  capability net_bind_service,
  capability kill,
  capability dac_override,
 
  /usr/sbin/apache2 mr,
  /etc/apache2/** r,
  /etc/mime.types r,
  /etc/hosts r,
  /etc/host.conf r,
  /etc/resolv.conf r,
  /etc/ssl/certs/** r,
  /etc/ssl/private/** r,
 
  /var/www/** r,
  /var/log/apache2/*.log w,
  /var/log/apache2/*.log a,
  /var/run/apache2/*.pid rw,
  /var/lock/apache2/** rwk,
  /var/cache/apache2/** rw,
  /run/apache2/** rw,
 
  /usr/lib/apache2/modules/*.so mr,
 
  /proc/*/status r,
  /proc/self/fd/ r,
 
  network inet stream,
  network inet6 stream,
}
EOF
}
 
write_mysqld_profile() {
  cat > "$MYSQLD_PROFILE_PATH" <<'EOF'
#include <tunables/global>
 
/usr/sbin/mysqld {
  #include <abstractions/base>
  #include <abstractions/nameservice>
 
  capability setuid,
  capability setgid,
  capability dac_override,
  capability sys_resource,
 
  /usr/sbin/mysqld mr,
  /etc/mysql/** r,
  /var/lib/mysql/ r,
  /var/lib/mysql/** rwk,
  /var/log/mysql/*.log w,
  /var/log/mysql/*.log a,
  /run/mysqld/mysqld.pid rw,
  /run/mysqld/mysqld.sock w,
  /tmp/** rwk,
 
  /proc/*/status r,
 
  network inet stream,
  network inet6 stream,
  network unix stream,
}
EOF
}
 
enforce_daemon_profile() {
  local label="$1" bin_path="$2" profile_path="$3" write_fn="$4" service_name="$5"
  local mode
 
  mode=$(profile_mode "$bin_path")
 
  if [ "$mode" = "missing" ]; then
    "$write_fn"
    if ! apparmor_parser -r "$profile_path" 2>/tmp/aa_load_err.$$; then
      echo "    ${bin_path}  [FAILED TO LOAD - see /tmp/aa_load_err.$$]"
      return
    fi
    mode="complain"
  fi
 
  if [ "$mode" = "enforce" ]; then
    printf '    %-25s enforce              [OK]\n' "$bin_path"
    ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
    return
  fi
 
  # mode is complain: switch to enforce, then verify the real service
  # this profile confines is still running before trusting the change.
  if aa-enforce "$profile_path" >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$service_name" 2>/dev/null; then
      printf '    %-25s complain -> enforce  [ENFORCED]\n' "$bin_path"
      ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
    else
      # Service not active/verifiable: revert to complain rather than
      # leave a production service down under an unverified profile.
      aa-complain "$profile_path" >/dev/null 2>&1 || true
      printf '    %-25s [REVERTED - %s not active after enforcement]\n' "$bin_path" "$service_name"
      COMPLAIN_COUNT=$((COMPLAIN_COUNT + 1))
    fi
  else
    printf '    %-25s [FAILED TO ENFORCE]\n' "$bin_path"
    COMPLAIN_COUNT=$((COMPLAIN_COUNT + 1))
  fi
}
 
enforce_daemon_profile "apache2" "$APACHE_BIN" "$APACHE_PROFILE_PATH" write_apache_profile "apache2"
enforce_daemon_profile "mysqld" "$MYSQLD_BIN" "$MYSQLD_PROFILE_PATH" write_mysqld_profile "mysql"
 
# Report any additional already-enforced profiles this project cares
# about (e.g. sshd), matching them exactly as aa-status already knows
# them, without re-touching their mode.
SSHD_MODE=$(profile_mode "/usr/sbin/sshd")
if [ "$SSHD_MODE" = "enforce" ]; then
  printf '    %-25s enforce              [OK]\n' "/usr/sbin/sshd"
  ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
elif [ "$SSHD_MODE" = "complain" ]; then
  printf '    %-25s complain             [NOT ENFORCED]\n' "/usr/sbin/sshd"
  COMPLAIN_COUNT=$((COMPLAIN_COUNT + 1))
fi
 
# ---------------------------------------------------------------------
# STEP 3: CUSTOM MEDDEFENSE BILLING-APP PROFILE
# ---------------------------------------------------------------------
echo "[*] Custom profile: ${CUSTOM_APP_PATH}"
 
mkdir -p "$(dirname "$CUSTOM_APP_PATH")" "${CUSTOM_APP_PATH%/*}/config" "${CUSTOM_APP_PATH%/*}/logs" 2>/dev/null || true
if [ ! -e "$CUSTOM_APP_PATH" ]; then
  cat > "$CUSTOM_APP_PATH" <<'PLACEHOLDER_EOF'
#!/bin/bash
# Placeholder for the MedDefense billing application binary/entrypoint.
# Real deployment replaces this file; the AppArmor profile below
# confines whatever binary occupies this exact path.
PLACEHOLDER_EOF
  chmod 750 "$CUSTOM_APP_PATH"
fi
 
cat > "$CUSTOM_PROFILE_PATH" <<EOF
#include <tunables/global>
 
${CUSTOM_APP_PATH} {
  #include <abstractions/base>
 
  ${CUSTOM_APP_PATH} mr,
  ${CUSTOM_APP_PATH%/*}/config/** r,
  ${CUSTOM_APP_PATH%/*}/logs/** rw,
  /var/lib/mysql-billing/** rw,
  /etc/meddefense/billing-app.conf r,
 
  deny /home/** rwx,
  deny /root/** rwx,
  deny /etc/shadow r,
  deny /etc/gshadow r,
 
  network inet stream,
}
EOF
 
if apparmor_parser -r "$CUSTOM_PROFILE_PATH" 2>/tmp/aa_custom_err.$$; then
  if aa-enforce "$CUSTOM_APP_PATH" >/dev/null 2>&1; then
    echo "    ${CUSTOM_APP_PATH}   [CREATED] [ENFORCED]"
    ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
  else
    echo "    ${CUSTOM_APP_PATH}   [CREATED] [ENFORCE FAILED]"
  fi
else
  echo "    ${CUSTOM_APP_PATH}   [PROFILE LOAD FAILED - see /tmp/aa_custom_err.$$]"
fi
 
# ---------------------------------------------------------------------
# STEP 4: UNCONFINED NETWORK-EXPOSED PROCESSES
# ---------------------------------------------------------------------
echo "[*] Unconfined network-exposed processes:"
 
# Every process with an unconfined AppArmor status, per aa-status.
mapfile -t UNCONFINED_BINS < <(aa-status 2>/dev/null | awk '/processes are unconfined/,/^$/' | grep -oE '^/[^ ]+' || true)
 
# Cross-reference against processes actually holding a listening
# network socket (ss -tulnp), so this reports only network-exposed
# unconfined processes, not every unconfined process on the box
# (e.g. short-lived shell utilities are unconfined by design and not
# relevant here).
LISTENING_BINS=$(ss -tulnp 2>/dev/null | grep -oE '"[^"]+"' | tr -d '"' | sort -u || true)
 
REPORTED_ANY=false
for bin in "${UNCONFINED_BINS[@]:-}"; do
  [ -z "$bin" ] && continue
  bname=$(basename "$bin")
  if printf '%s\n' "$LISTENING_BINS" | grep -qx "$bname"; then
    printf '    %-25s [UNCONFINED - Profile recommended]\n' "$bin"
    UNCONFINED_COUNT=$((UNCONFINED_COUNT + 1))
    REPORTED_ANY=true
  fi
done
if [ "$REPORTED_ANY" = false ]; then
  echo "    (none found)"
fi
 
# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
echo "Profiles in enforce: ${ENFORCE_COUNT} | Complain: ${COMPLAIN_COUNT} | Unconfined: ${UNCONFINED_COUNT}"
