#!/bin/bash
#
# 2-lynis_parse.sh
#
# Goal: parse a Lynis .dat report file (the key-value report Lynis writes
# to /var/log/lynis-report.dat after every audit) into a structured JSON
# summary containing the hardening index and every warning[], suggestion[],
# and manual_check[] finding.
#
# This is the bridge between a human-readable Lynis audit and this
# project's own automated, machine-readable workflow: the JSON this
# script produces is what a gap-analysis script (cross-referencing
# against cis_profile.json from Task 1) or a before/after delta report
# would actually consume, not the raw .dat file or the interactive
# terminal output.
#
# Usage: ./2-lynis_parse.sh /path/to/lynis-report.dat
# Output: a JSON object on standard output (redirect it yourself, this
# script does not write a file directly, matching the task's own
# expected usage: ./2-lynis_parse.sh <file> | jq '.' > lynis_findings.json)
 
set -euo pipefail
 
# ---------------------------------------------------------------------
# ARGUMENT VALIDATION
# ---------------------------------------------------------------------
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <path-to-lynis-report.dat>" >&2
  exit 1
fi
 
REPORT_FILE="$1"
 
if [ ! -f "$REPORT_FILE" ]; then
  echo "ERROR: report file not found: ${REPORT_FILE}" >&2
  exit 1
fi
 
if [ ! -r "$REPORT_FILE" ]; then
  echo "ERROR: report file is not readable (try running with sudo): ${REPORT_FILE}" >&2
  exit 1
fi
 
# ---------------------------------------------------------------------
# JSON ESCAPE HELPER (used only in the no-jq fallback path below)
# ---------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}
 
# ---------------------------------------------------------------------
# EXTRACT HARDENING INDEX
# ---------------------------------------------------------------------
# The .dat report stores this as a plain key=value line, e.g.
# "hardening_index=62", distinct from the decorated "Hardening index :
# 62 [####...]" line shown in the interactive terminal output.
HARDENING_INDEX=$(grep '^hardening_index=' "$REPORT_FILE" | head -1 | cut -d= -f2 || true)
if [ -z "$HARDENING_INDEX" ]; then
  HARDENING_INDEX="null"
fi
 
# ---------------------------------------------------------------------
# EXTRACT FINDINGS (warning[], suggestion[], manual_check[])
# ---------------------------------------------------------------------
# Each line has the form: KEY[]=test_id|message|extra_field|extra_field|
# We only need the first two pipe-delimited fields (test_id, message);
# any additional fields (often a specific config change suggestion, or
# "-" placeholders) are not part of this task's required schema.
extract_findings() {
  local severity="$1"
  grep "^${severity}\[\]=" "$REPORT_FILE" 2>/dev/null | \
    sed -E "s/^${severity}\[\]=([^|]*)\|([^|]*)\|.*/${severity}\t\1\t\2/" || true
}
 
ALL_FINDINGS_TSV=$(
  {
    extract_findings "warning"
    extract_findings "suggestion"
    extract_findings "manual_check"
  }
)
 
# ---------------------------------------------------------------------
# BUILD JSON OUTPUT
# ---------------------------------------------------------------------
if command -v jq >/dev/null 2>&1; then
  # Preferred path: jq handles JSON escaping correctly for any message
  # content (quotes, backslashes, unicode) far more reliably than manual
  # shell string escaping ever could.
  FINDINGS_JSON=$(
    printf '%s\n' "$ALL_FINDINGS_TSV" \
      | jq -R -s '
          split("\n")
          | map(select(length > 0))
          | map(split("\t"))
          | map({severity: .[0], test_id: .[1], message: .[2]})
        '
  )
 
  if [ "$HARDENING_INDEX" = "null" ]; then
    jq -n --argjson findings "$FINDINGS_JSON" \
      '{hardening_index: null, findings: $findings}'
  else
    jq -n --argjson idx "$HARDENING_INDEX" --argjson findings "$FINDINGS_JSON" \
      '{hardening_index: $idx, findings: $findings}'
  fi
else
  # Fallback path: jq is not installed. Build the same JSON structure
  # manually, using the same escaping helper proven in Task 0 and
  # Task 1 of this project. Functionally equivalent output, just built
  # without an external dependency.
  echo "WARNING: jq not found, using manual JSON construction fallback." >&2
 
  {
    printf '{\n  "hardening_index": %s,\n  "findings": [\n' "$HARDENING_INDEX"
    FIRST=true
    while IFS=$'\t' read -r sev tid msg; do
      [ -z "$sev" ] && continue
      if [ "$FIRST" = true ]; then FIRST=false; else printf ',\n'; fi
      printf '    {\n'
      printf '      "severity": "%s",\n' "$(json_escape "$sev")"
      printf '      "test_id": "%s",\n' "$(json_escape "$tid")"
      printf '      "message": "%s"\n' "$(json_escape "$msg")"
      printf '    }'
    done <<< "$ALL_FINDINGS_TSV"
    printf '\n  ]\n}\n'
  }
fi
