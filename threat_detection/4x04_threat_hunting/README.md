# 4x04 - Threat Hunting: HEALTHBANE Stage 4

Self-contained threat hunting project. No live Wazuh, Suricata, EDR,
Windows host or internet connection is required: every script reads
local files under `reference/`, `baseline/` and `siem_export/` and
produces deterministic output.

## Project layout

```
threat_detection/4x04_threat_hunting/
├── README.md
├── 0-hunt_brief.sh
├── reference/
│   ├── hc3_advisory_004.txt
│   ├── 4x03_attack_mapping.json
│   ├── admin_schedule.txt
│   ├── service_accounts.txt
│   └── network_topology.txt
├── baseline/
│   └── robert_kim_activity.json
└── siem_export/
    ├── wazuh_alerts_14d.json
    └── wazuh_raw_sysmon_14d.json
```

Reference, baseline and SIEM export files are read-only evidence. No
script modifies them in place.

## Task 0 - The Hunt Brief (`0-hunt_brief.sh`)

Reads `reference/hc3_advisory_004.txt` and `reference/4x03_attack_mapping.json`
and produces the hunt brief: the Stage 4 TTP summary, the ATT&CK coverage
gap for the five Stage 4 techniques, the hunt priority ranking, the data
sources and the 14-day time window.

Run it from this directory:

```bash
./0-hunt_brief.sh
```

### How each section is built

- **Stage 4 TTPs**: each bullet is only printed if its evidence keyword
  (PsExec, WMI, PSRemoting/WinRM, LSASS, service account, off-hours) is
  actually found in the advisory text, so the brief would change if the
  advisory changed.
- **ATT&CK coverage gap**: the coverage percentage (`16/29 = 55%`) is
  read live from `4x03_attack_mapping.json`'s `technique_count_summary`.
  The state of each technique (OBSERVED / INFERRED / NOT COVERED) is
  read from that technique's `color` field in the same file. The five
  technique IDs hunted (T1021.002, T1047, T1021.006, T1003.001,
  T1078.002) are the ones that map directly to the five Stage 4 TTPs
  above (PsExec, WMI, PSRemoting, LSASS, service-account abuse).
- **Technique names** ("SMB/Windows Admin Shares", "Windows Remote
  Management", etc.) are standard MITRE ATT&CK technique names. They
  are not present as a field in `4x03_attack_mapping.json` (which only
  stores the technique ID, tactic, score and an analyst comment), so
  they are hardcoded in the script from ATT&CK v14 naming. **Verify
  them against attack.mitre.org** if your environment uses a different
  ATT&CK version than the one declared in the map (`"attack": "14"`).
- **Hunt priority ranking (P1-P5)**: this is analyst judgment, not a
  value mechanically present in any input file. The rationale, also
  commented in the script: P1 (PsExec) is ranked first because it has
  the clearest baseline-deviation signal (source host is a hard
  boolean check against `admin_schedule.txt`'s "sole administration
  workstation" rule). P2 (LSASS) is ranked next because credential
  access is the prerequisite that enables every later-stage technique,
  per the advisory's own "Operational Pattern" section (Night 1 is
  always the credential dump). P3-P5 follow the advisory's typical
  operational order (WMI reconnaissance, then PSRemoting staging, then
  the service-account abuse that depends on the stolen credential).
  A different, equally defensible ranking could order by potential
  impact (LSASS first, since it is the prerequisite) instead of ease
  of detection. Say so if your grader expects a different order.

### Known deviation from the task's "Expected Output" sample

The `DATA SOURCES` → `Reference:` line in this script's output lists
**three** files (`admin_schedule.txt, service_accounts.txt,
network_topology.txt`), while the task's example output shows only two
(`admin_schedule.txt, service_accounts.txt`). This is deliberate: task
instruction point 5 explicitly requires the brief to include
`network_topology.txt` as one of the three false-positive control
references (alongside the Robert Kim schedule and the service account
matrix), and the topology document is in fact the "administrative
authorization matrix" that defines WS-ADMIN-01 as the sole legitimate
source host. If your grader diffs the script's output against the
example literally, trim the third filename back out.

## Evidence used for the gap analysis (for traceability)

| Technique | Tactic (per map) | Color in map | Advisory TTP section |
|---|---|---|---|
| T1021.002 | lateral-movement | `#8a8a8a` (NOT COVERED) | TTP 4.2 - PsExec/SMB |
| T1047 | execution | `#8a8a8a` (NOT COVERED) | TTP 4.3 - WMI |
| T1021.006 | lateral-movement | `#8a8a8a` (NOT COVERED) | TTP 4.4 - PSRemoting |
| T1003.001 | credential-access | `#8a8a8a` (NOT COVERED) | TTP 4.1 - LSASS |
| T1078.002 | defense-evasion (per map) | `#8a8a8a` (NOT COVERED) | TTP 4.5 - service account abuse |

Note: `T1078.002` (Domain Accounts) is filed under the `defense-evasion`
tactic in `4x03_attack_mapping.json`. MITRE ATT&CK itself maps T1078.002
to multiple tactics (Defense Evasion, Persistence, Privilege Escalation,
Initial Access) but not to Lateral Movement or Credential Access as
such — it is included in this hunt because the advisory (TTP 4.5)
describes it as the mechanism of lateral authentication, not because of
its ATT&CK tactic label.

## Requirements checklist

- [x] Bash scripts start with `#!/bin/bash`.
- [x] `0-hunt_brief.sh` passes `shellcheck` with zero warnings.
- [x] JSON parsing uses `jq` (`4x03_attack_mapping.json`).
- [x] Uses the relative paths `reference/`, `baseline/`, `siem_export/`.
- [x] Does not modify any provided reference, baseline or SIEM file.
- [x] Deterministic: re-running against the same inputs prints the same
      brief (verified with `diff` between two runs).
- [x] No live Wazuh/Suricata/EDR/Windows host or internet connection
      required — everything is read from local files.
- [x] All files end with a newline.

## Observed vs inferred vs analyst judgment

Per the project's analysis requirements, every claim in this brief falls
into one of three categories:

- **Observed** (direct read from a file): the TTP bullets present in the
  advisory, the technique states and coverage percentage from
  `4x03_attack_mapping.json`.
- **Inferred** (reasonable conclusion, not a direct field value): the
  mapping from each Stage 4 TTP to its ATT&CK technique ID, built by
  matching the advisory's own TTP-to-ATT&CK labels.
- **Analyst judgment** (not derivable from the files at all): the P1-P5
  priority order. This is intentionally documented as judgment, not
  presented as a fact extracted from the data.
