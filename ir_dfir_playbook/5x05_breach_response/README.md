# 5x05 - The Breach

> You do not rise to the incident; you fall to the playbook you actually have, not the one you wish you had written.

## Scenario recap

Sunday, 2026-04-20, 19:43Z. Network Engineer Mike Torres calls the on-call IR line: a nurse at Main
reports her workstation (CS-WS-101) is unresponsive with desktop files that "look different," the
scheduling server (SCHED-SVR-01) has shown pinned CPU and disk queue for roughly 90 minutes, and a
SIEM alert (rule `wz-edr-200214`) shows a disguised service (`WinHealthSvc`, masquerading as a
Microsoft component) installed near-simultaneously on three clinical workstations
(CS-WS-104/107/112). Torres captured a memory snapshot of CS-WS-101 before calling, without
computing a hash at acquisition - the same gap flagged in incident IR-2026-0414-01.

This capstone owns the response from this first call through the board brief the next morning:
triage, containment, investigation, communication, eradication, recovery, and improvement, using
only what was already built in 5x00 through 5x04. No new technique is introduced and no procedural
guidance is given.

## Grounding materials

- `torres_call_transcript.md` - the initial operational signal that triggered the incident
  declaration (5x05/)
- `fileserver_access.sample.json`, `proxy_72h.sample.jsonl`, `sysmon_multihost.sample.jsonl` -
  forensic artifact samples (5x05/), not yet used beyond this task
- `ir_dfir_playbook/5x00_incident_response/severity_matrix.md` - authoritative severity criteria
- `ir_dfir_playbook/5x00_incident_response/ir_team_structure.yaml` - authoritative roles, owners,
  and escalation rules
- `ir_dfir_playbook/5x00_incident_response/playbook_credential_exposure.yaml` (PB-002) and
  `playbook_clinical_degradation.yaml` (PB-003) - the two existing playbooks evaluated for
  activation

## Task 0 - Activate the IR Program

`ir_activation.md` - the formal declaration record: incident ID IR-2026-0420-01, declared SEV2 at
19:52Z per the severity matrix's single-clinical-workstation malware threshold (met and exceeded by
three hosts), PB-003 activated as the closest available match despite an imperfect trigger fit (a
documented playbook gap, not a clean activation), three notifications within the first four
minutes, and a first executive status update to Dr. Patricia Morales at 20:05Z.

`incident_timeline.md` - the append-only record opened with three entries: the initial user
reports, the SIEM alert, and the incident declaration. Updated across every subsequent task in this
capstone.

## Contents

| File | Task | Description |
|---|---|---|
| `ir_activation.md` | 0 | Formal incident declaration record |
| `incident_timeline.md` | 0 | Append-only incident timeline |

*(This table will grow as further tasks in this module are completed.)*
