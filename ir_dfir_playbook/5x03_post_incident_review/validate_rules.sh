#!/bin/bash
#
# validate_rules.sh - Module 5x03, Task 5
#
# Tests the Sigma detection rule(s) in this directory against the incident sample
# (expected to match) and the clean 30-day baseline (expected false-positive rate
# under 0.1% of total events).
#
# NOTE: this module has no Task 4. Only one Sigma rule exists from Task 3
# (sigma_powershell_msbuild_lolbin.yml). The RULES array below lists every rule
# this script tests; if a second rule is ever added, add its filename here and
# this script will test it the same way without further changes.
#
# Matching approach: sigma-cli has no built-in backend here that queries flat
# JSONL files directly, and this lab's Sysmon export uses lowercase field names
# (image, parent_image, dst_hostname, ...) rather than the canonical Sysmon/Sigma
# PascalCase names (Image, ParentImage, DestinationHostname, ...) the rule itself
# is written against. This script is the "compatible log matching tool" the task
# allows in that case: it parses each rule's actual YAML (detection logic is read
# from the file, never hand-duplicated) and evaluates it against each JSONL event
# after applying an explicit field-name mapping, documented below in the Python
# block. Only events whose event_type matches the rule's logsource.category are
# considered eligible to match, exactly as a real Sigma backend would scope
# evaluation to the declared logsource.

set -uo pipefail

RULES=("sigma_powershell_msbuild_lolbin.yml")
SAMPLES=("incident_sysmon.jsonl" "clean_sysmon.jsonl")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_match() {
  local rule_file="$1"
  local sample_file="$2"
  python3 - "$rule_file" "$sample_file" << 'PYEOF'
import sys, json, yaml, fnmatch

rule_path, sample_path = sys.argv[1], sys.argv[2]

# Canonical Sigma/Sysmon field name -> this lab's lowercase JSONL field name.
FIELD_MAP = {
    "Image": "image",
    "ParentImage": "parent_image",
    "CommandLine": "cmdline",
    "ParentCommandLine": "parent_cmdline",
    "User": "user",
    "DestinationHostname": "dst_hostname",
    "DestinationIp": "dst_ip",
    "DestinationPort": "dst_port",
}
# Sigma logsource.category -> this lab's event_type value.
CATEGORY_MAP = {
    "process_creation": "process_create",
    "network_connection": "network_connection",
}

with open(rule_path) as f:
    rule = yaml.safe_load(f)

logsource = rule.get("logsource", {})
category = logsource.get("category")
expected_event_type = CATEGORY_MAP.get(category, category)

detection = rule["detection"]
condition = detection["condition"].strip()
selections = {k: v for k, v in detection.items() if k != "condition"}


def field_and_modifier(key):
    if "|" in key:
        field, modifier = key.split("|", 1)
    else:
        field, modifier = key, "equals"
    return FIELD_MAP.get(field, field), modifier


def value_matches(event_value, modifier, candidates):
    if event_value is None:
        return False
    if not isinstance(candidates, list):
        candidates = [candidates]
    for cand in candidates:
        if modifier == "endswith":
            if event_value.endswith(cand):
                return True
        elif modifier == "startswith":
            if event_value.startswith(cand):
                return True
        elif modifier == "contains":
            if cand in event_value:
                return True
        else:  # equals / no modifier
            if event_value == cand:
                return True
    return False


def selection_matches(selection_def, event):
    # All fields within one selection are AND-ed (Sigma semantics).
    for key, candidates in selection_def.items():
        field, modifier = field_and_modifier(key)
        if not value_matches(event.get(field), modifier, candidates):
            return False
    return True


def eval_condition(cond_str, selection_results):
    # Minimal evaluator: supports "A and B", "A or B", "not A", single name.
    tokens = cond_str.split()
    if len(tokens) == 1:
        return selection_results.get(tokens[0], False)
    if len(tokens) == 2 and tokens[0] == "not":
        return not selection_results.get(tokens[1], False)
    if len(tokens) == 3 and tokens[1] in ("and", "or"):
        left = selection_results.get(tokens[0], False)
        right = selection_results.get(tokens[2], False)
        return (left and right) if tokens[1] == "and" else (left or right)
    raise ValueError(f"Unsupported condition syntax for this script: {cond_str!r}")


total_events = 0
matches = []

with open(sample_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        total_events += 1
        event = json.loads(line)
        if expected_event_type is not None and event.get("event_type") != expected_event_type:
            continue
        sel_results = {name: selection_matches(sdef, event) for name, sdef in selections.items()}
        if eval_condition(condition, sel_results):
            matches.append(event)

rate = (len(matches) / total_events * 100) if total_events else 0.0
print(f"TOTAL={total_events}")
print(f"MATCHES={len(matches)}")
print(f"RATE={rate:.3f}")
for ev in matches:
    ts = ev.get("ts")
    host = ev.get("host")
    pid = ev.get("pid")
    image = ev.get("image")
    parent = ev.get("parent_image")
    print(f"MATCH_DETAIL={ts} host={host} pid={pid} image={image} parent={parent}")
PYEOF
}

for rule in "${RULES[@]}"; do
  rule_path="$SCRIPT_DIR/$rule"
  if [[ ! -f "$rule_path" ]]; then
    echo "ERROR: rule file not found: $rule_path" >&2
    exit 1
  fi
  echo "=================================================================="
  echo "Rule: $rule"
  echo "=================================================================="
  for sample in "${SAMPLES[@]}"; do
    sample_path="$SCRIPT_DIR/$sample"
    if [[ ! -f "$sample_path" ]]; then
      echo "ERROR: sample file not found: $sample_path" >&2
      exit 1
    fi
    echo
    echo "  [$sample]"
    result="$(run_match "$rule_path" "$sample_path")"
    total="$(echo "$result" | grep '^TOTAL=' | cut -d= -f2)"
    count="$(echo "$result" | grep '^MATCHES=' | cut -d= -f2)"
    rate="$(echo "$result" | grep '^RATE=' | cut -d= -f2)"
    echo "  Total events: $total"
    echo "  Matches: $count"
    if [[ "$sample" == "incident_sysmon.jsonl" ]]; then
      echo "  Match rate: ${rate}%"
      if [[ "$count" -gt 0 ]]; then
        echo "  Verdict: PASS (rule fired on the incident data)"
      else
        echo "  Verdict: FAIL (rule did not fire on the incident data)"
      fi
    else
      echo "  False positive rate: ${rate}%"
      fp_check=$(python3 -c "print(1 if float('$rate') < 0.1 else 0)")
      if [[ "$fp_check" == "1" ]]; then
        echo "  Verdict: PASS"
      else
        echo "  Verdict: REVIEW (false positive rate at or above 0.1% target)"
      fi
    fi
    echo "$result" | grep '^MATCH_DETAIL=' | sed 's/^MATCH_DETAIL=/  Matched event: /'
    if [[ "$sample" == "clean_sysmon.jsonl" && "$count" == "0" ]]; then
      echo "  False positive pattern: none - no events matched in the clean baseline."
    fi
  done
  echo
done
