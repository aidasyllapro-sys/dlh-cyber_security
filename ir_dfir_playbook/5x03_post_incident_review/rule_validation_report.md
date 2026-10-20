# Rule Validation Report: IR-2026-0414-01

## Scope note

This module has no Task 4 (confirmed with the analyst). Only one Sigma rule exists to
validate: `sigma_powershell_msbuild_lolbin.yml` from Task 3. `validate_rules.sh` is written so
that a second rule file could be added to its `RULES` array later without changes to the
script's logic, but for this report there is exactly one rule and one result set.

## Method

`validate_rules.sh` reads the rule's actual YAML (`detection`, `logsource.category`), applies an
explicit field-name mapping (the lab's JSONL uses lowercase Sysmon field names such as `image`
and `parent_image`, not the canonical PascalCase `Image`/`ParentImage` the rule is written
against), and evaluates it event-by-event against each sample, scoped to events whose
`event_type` matches the rule's `logsource.category` (`process_creation` -> `process_create`),
exactly as a real Sigma backend would scope evaluation to the declared logsource. Totals, match
counts, and match rate are computed from each sample's full event count.

## Results
==================================================================
Rule: sigma_powershell_msbuild_lolbin.yml

[incident_sysmon.jsonl]
Total events: 17
Matches: 2
Match rate: 11.765%
Verdict: PASS (rule fired on the incident data)
Matched event: 2026-04-14T02:46:58Z host=WST-WS-031 pid=8104 image=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe parent=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Matched event: 2026-04-14T03:27:13Z host=WST-WS-017 pid=5108 image=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe parent=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

[clean_sysmon.jsonl]
Total events: 21
Matches: 0
False positive rate: 0.000%
Verdict: PASS
False positive pattern: none - no events matched in the clean baseline.


## Findings

**Did the rule fire on the incident data? Expected: yes.**
Yes. The rule produced exactly 2 matches on `incident_sysmon.jsonl`, both `process_create`
events for `MSBuild.exe` spawned directly by `powershell.exe`:
- `2026-04-14T02:46:58Z`, host `WST-WS-031`, PID 8104 (the original compromise)
- `2026-04-14T03:27:13Z`, host `WST-WS-017`, PID 5108 (the lateral-movement re-use of the same
  technique after Pass-the-Ticket)

Both matches correspond to the two confirmed `T1127.001` events documented in
`forensic_findings_summary.md` (`ART-002-M01`) and `control_effectiveness.yaml`
(phase: PowerShell to MSBuild LOLBin execution). No other event in the 17-line incident sample
matched, which is correct: the sample's other PowerShell and MSBuild-related lines are a
`file_create`, `network_connection`, `image_load`, `registry_set`, and `process_terminate`
event - none of them a `process_create` event, so none are in scope for a
`logsource.category: process_creation` rule, and none should match.

**What was the false positive rate on the clean baseline? Target: under 0.1%.**
0.000% (0 matches out of 21 total events). This is already under the 0.1% target.

The clean sample specifically includes the scenario this rule is designed to tell apart from
the real attack: a developer building `LabHealthCheck.sln` through Visual Studio, where
`devenv.exe` launches `MSBuild.exe` directly (line 2 of `clean_sysmon.jsonl`). This does **not**
match `selection_parent` (the parent is `devenv.exe`, not `powershell.exe`/`pwsh.exe`/
`wscript.exe`/`cscript.exe`), so the rule correctly does not flag it. The clean sample also
includes a legitimate `powershell.exe` to `dotnet.exe` build invocation (`dotnet build`); this
matches `selection_parent` but not `selection_child` (`dotnet.exe` is not in the LOLBin list the
rule targets), so it is also correctly not flagged.

**Tuning.**
None was needed. The rule as written in Task 3 already produces a 0.000% false positive rate
against the provided 30-day clean baseline, well under the 0.1% target, so
`sigma_powershell_msbuild_lolbin.yml` is unchanged from its Task 3 version - no tuned
replacement was committed for this report.

## Caveat on sample size

The clean baseline provided for this lab is 21 events over "30 days," not the tens or hundreds
of thousands of events a real 30-day Sysmon export from a clinical-workstation fleet would
contain. A 0.000% rate on 21 events is a much weaker statistical guarantee than the same rate on
a production-scale sample. This rule should be re-validated against the full-volume production
baseline before being treated as confirmed at scale, not just against this lab sample.
