# IR Activation: IR-2026-0420-01

- **incident_id:** IR-2026-0420-01
- **declared_at:** 2026-04-20T19:52Z
- **declared_by:** Aida Sylla, on-call IR
- **initial_severity:** SEV2

- **reasoning:**
  Per the MedDefense severity matrix, SEV1 requires confirmed ransomware across multiple sites,
  confirmed large-scale exfiltration, or ICU/OR/patient-monitoring equipment offline during active
  care - none of which is confirmed at declaration time: every signal is confined to Site A (Main
  campus), no encryption has been confirmed, and the affected systems are a clinical coordinator
  workstation and a scheduling server, not monitoring or OR equipment. SEV2's "malware confirmed on
  a single workstation at a clinical site" threshold is met and exceeded: the SIEM alert (rule
  wz-edr-200214) shows a service (WinHealthSvc, masquerading as a Microsoft binary at
  C:\ProgramData\Microsoft\svchost32.exe) installed near-simultaneously on three clinical
  workstations (CS-WS-104, CS-WS-107, CS-WS-112), a pattern consistent with scripted deployment
  rather than an isolated incident. CS-WS-101's reported file changes and SCHED-SVR-01's 90-minute
  disk anomaly are not yet independently confirmed as related or malicious, but both align with the
  same site and window. Declared SEV2 rather than SEV1 because the matrix's specific SEV1 triggers
  are not yet met; this is treated as a strong SEV1 candidate pending confirmation of ransomware
  activity, multi-site spread, or exfiltration scope, and will be reassessed at every status update
  per the matrix's escalation rule.

- **playbook_activated:** PB-003 (`playbook_clinical_degradation.yaml`)

  Activated as the closest available match despite an imperfect fit: its triggers are written
  specifically for the radiology imaging server, not for CS-WS-101, SCHED-SVR-01, or
  CS-WS-104/107/112. It is activated for its procedural structure - IR_Commander-led triage, a
  mandatory coordination step with the On-Call Clinical Lead before isolating a system clinical
  staff currently depend on, and its decision-point/trade-off format for containment under active
  patient care - not because its stated triggers match. PB-002 (`playbook_credential_exposure.yaml`)
  does not apply either: its triggers require a reported phishing/credential-entry event, which has
  not occurred here. This is a documented playbook gap, not a clean activation: no existing playbook
  was written for a multi-host, service-persistence-style compromise. Recommended as a post-incident
  action: build a dedicated malware/multi-host playbook.

- **notifications:**
    - 19:52Z: James Chen (IR_Commander, SOC Lead) - notified by bridge handoff from Torres; assumes
      incident command per severity_mapping SEV2 on_detection escalation.
    - 19:54Z: Robert Kim (Technical_Lead, Infrastructure Lead) - notified; directed to coordinate
      evidence acquisition across CS-WS-104, CS-WS-107, CS-WS-112, and SCHED-SVR-01, building on
      Torres's existing CS-WS-101 memory capture.
    - 19:56Z: Sarah Park (Scribe, IT Director) - notified; begins `incident_timeline.md` as the
      authoritative record per her role definition in `ir_team_structure.yaml`.

- **first_communication:** executive_status_update sent to Dr. Patricia Morales (Executive Sponsor,
  CISO) at 20:05Z:

  > Dr. Morales, this is a status update on IR-2026-0420-01, declared SEV2 at 19:52Z. At 19:43Z,
  > Network Engineer Mike Torres reported a possible file change on a clinical coordinator
  > workstation at Main (CS-WS-101) alongside sustained abnormal disk activity on the scheduling
  > server (SCHED-SVR-01); a SIEM alert subsequently confirmed a disguised service installed on
  > three additional clinical workstations within a twelve-minute window this afternoon. Nothing is
  > yet confirmed as ransomware, multi-site, or involving patient data exfiltration, which is why
  > this has not been declared SEV1, but the pattern across four hosts warrants close monitoring and
  > I will escalate immediately if any SEV1 trigger is met. IR_Commander James Chen and
  > Technical_Lead Robert Kim are actively coordinating evidence collection and triage across all
  > affected hosts. Next update by 21:00Z or sooner if the situation changes.
