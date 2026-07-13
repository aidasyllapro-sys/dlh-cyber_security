# MedDefense Health Systems: Control gap analysis

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Control Summary Matrix (`4-control_inventory.md`), incident log (`1-incident_classification.md`), billing-srv-01 root cause analysis (`2-root_cause_analysis.md`), physical walk-through (`3-physical_assessment.md`), and the underlying controls artifacts **Purpose:** Identify systematic gaps in MedDefense's control framework by analyzing what is absent from the Control Summary Matrix, not just what is present, and connect each gap to concrete risk.

---

## Gap inventory

```
Gap ID: G-001
Gap Description: Logs are generated in multiple places (FortiGate,
  Windows Event Viewer, Linux syslog, Apache logs, EHR vendor audit log)
  but nothing aggregates them, correlates events across systems, or
  generates automated alerts. Every source is reviewed manually and only
  "when something breaks."
Category x Function Missing: Technical Detective (specifically:
  correlation and alerting capability. Raw logging exists, but the
  Detective Function of actually surfacing an incident does not)
Affected Asset(s) or Zone: Entire IT environment i.e. network, servers,
  and the EHR application
Risk if Unaddressed: Availability, Integrity and Confidentiality —
  an attacker who bypasses preventive controls can operate undetected
  indefinitely, because no system is watching for the pattern across
  sources. This is not theoretical: the cryptominer on billing-srv-01
  (see root cause analysis) went unnoticed for months and was only
  found because a sysadmin happened to run `top` while investigating a
  performance complaint, not because any control detected it.
Evidence: Artifact 8 (Log management) explicitly states "No centralized
  log management system exists. No automated alerting on security
  events." The control summary matrix shows multiple technical detective
  controls (C-003, C-006, C-014, C-015, C-016), but every one of them is
  a passive, siloed log that none triggers an alert.
```

```
Gap ID: G-002
Gap Description: Antivirus/anti-malware protection (Sophos) is deployed
  only on Windows 10/11 workstations. Windows servers (15) have no
  coverage because the server-protection license was never purchased,
  and Linux servers (0 covered) are entirely outside the current Sophos
  tier's supported platforms.
Category x Function Missing: Technical Preventive (control exists in
  the organization, but does not cover a critical class of assets)
Affected asset(s) or zone: All 15 Windows servers and all Linux servers
  — including ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, ad-dc-02,
  file-srv-01, web-srv-01, backup-srv-01
Risk if Unaddressed: Integrity and Availability. Servers, which host
  the organization's most critical services and data, have no automated
  mechanism to prevent or flag malicious software execution. This gap is
  not hypothetical: it is the exact condition that allowed a
  cryptocurrency miner to run undetected on billing-srv-01 (a Linux
  server) for an extended period.
Evidence: Artifact 4 (Sophos Antivirus Status Report) explicitly states
  Windows servers are "NOT covered — server protection license not
  purchased" and Linux servers are "NOT covered — not supported by
  current Sophos tier." Marcus Webb requested server protection four
  months prior; the budget was not approved.
```

```
Gap ID: G-003
Gap Description: The ~25 iPads used by physicians for patient rounds
  are not enrolled in any Mobile Device Management (MDM) or Enterprise
  Mobility Management (EMM) solution, meaning MedDefense has no ability
  to enforce configuration, encryption, remote wipe, or patching on
  these devices.
Category x Function Missing: Technical Preventive (no management/
  control layer exists for this device class at all)
Affected Asset(s) or Zone: ~25 physician iPads (Central), and by
  extension whatever clinical/patient data they access during rounds
Risk if Unaddressed: Confidentiality and Availability — an unmanaged,
  mobile device with access to clinical systems is a plausible loss/
  theft scenario with no remote-wipe capability, and no way to confirm
  the device is running a supported, patched OS.
Evidence: Environment Summary (Task 0) lists iPad management status as
  explicitly "unclear." Artifact 4 confirms directly: "iPads used by
  physicians are not in scope (no MDM/EMM solution)."
```

```
Gap ID: G-004
Gap Description: Physical monitoring (cameras) exists only at building
  entrances, the ER entrance, and the parking garage entrance. The
  server room and the second-floor network closet, the 2 locations
  identified during the walk-through as having unrestricted physical
  access, have no camera coverage at all.
Category x Function Missing: Physical Detective (specifically for
  these two zones; Physical Preventive is also weak here (see the
  walk-through) but there is zero Physical Detective coverage of any
  kind for these rooms)
Affected Asset(s) or Zone: Server room (all core Central infrastructure)
  and the second-floor network closet (switches, patch panels, posted
  credentials)
Risk if Unaddressed: Availability, Integrity and Confidentiality. If
  the weak physical access controls identified in the walk-through
  (Observations 1 and 2) are ever exploited, there would be no camera
  footage, no log, and no way to determine who entered, when, or what
  they did. Detection would depend entirely on someone noticing a
  physical symptom afterward.
Evidence: Artifact 6 (Camera System notes) explicitly states "No
  cameras in server room area, network closets or administrative wing."
  This directly corroborates Observation 1 and Observation 2 from the
  physical walk-through, which independently flagged the absence of a
  camera at the server room door.
```

```
Gap ID: G-005
Gap Description: No tested, documented incident response plan exists,
  and the only tested recovery procedure (a partial restore of
  file-srv-01, 8 months prior) took 6 hours for a single server. A full
  disaster recovery test has never been performed. There is no
  documented procedure for clinical operations if Central loses power
  beyond the ~20 minutes its UPS can sustain.
Category x Function Missing: Administrative Corrective (and, related,
  Technical Corrective beyond the single backup mechanism identified in
  the matrix)
Affected Asset(s) or Zone: The entire organization's ability to recover
  from any significant incident, most acutely, all systems excluded
  from the nightly backup job (pacs-srv-01, ad-dc-02, print-srv-01,
  ws-srv-01 at Westside, medical device configurations, and O365 data)
Risk if Unaddressed: Availability. When the January ransomware incident
  occurred, response was, in James's own words, "improvised for 4 days"
  by James, Sarah, and Marcus directly. Without a documented, tested
  plan, every future incident carries the same risk of an ad hoc,
  slower, and more error-prone response, and several systems (PACS,
  the secondary domain controller, Westside's server) have no
  documented recovery path at all.
Evidence: Environment Summary (Task 0, Known Unknowns) states no formal
  incident response, business continuity, or disaster recovery plan
  exists. Artifact 5 (Backup Configuration) confirms "Full DR test:
  Never performed" and lists six categories of systems/data explicitly
  excluded from backup.
```

```
Gap ID: G-006
Gap Description: No periodic review or audit process exists to verify
  that documented policies (e.g., the password policy, the SSH
  key-only-authentication migration) are actually being followed in
  practice. The password policy itself was last reviewed 18 months ago.
Category x Function Missing: Administrative Detective
Affected Asset(s) or Zone: Organization-wide, specifically, no process
  would catch that SSH password authentication remains enabled on every
  Linux server except ehr-srv-01, or that a shared PACS login is in use
  in Radiology, until each was reported individually and, in some cases,
  never acted upon
Risk if Unaddressed: Integrity and Confidentiality. Policy documents
  create an appearance of control that is not verified against reality.
  Multiple findings elsewhere in this assessment (shared PACS account,
  incomplete SSH hardening, generic server-room badge) show that stated
  policy and actual practice have already diverged, with no
  administrative mechanism in place to detect that divergence on its
  own.
Evidence: The Control Summary Matrix (Task 4) shows no control at all in
  the Administrative Detective cell. Artifact 3 (Password Policy) shows
  no audit/review cadence beyond an 18-month-old "last reviewed" date;
  Artifact 2 confirms the SSH hardening was completed on only one server
  out of many, and, per Tom Reeves, no one has had time to check or
  extend it since.
```

```
Gap ID: G-007
Gap Description: No compensating controls are documented for assets
  that cannot receive their ideal control. Two examples already
  identified elsewhere in this assessment: the MRI scanner running
  Windows XP (unsupported, unpatchable) with no evidence of network
  isolation, and Linux servers other than ehr-srv-01 that still permit
  SSH password authentication with no interim mitigation (such as
  IP allow-listing or a jump host) while key-only migration remains
  incomplete.
Category x Function Missing: Technical Compensating (empty across the
  entire matrix)
Affected Asset(s) or Zone: MRI scanner (Central Radiology), and all
  Linux servers pending SSH key-only migration
Risk if Unaddressed: Confidentiality, Integrity and Availability. An
  unpatchable device or a known-weak authentication method left with no
  alternative safeguard remains exploitable indefinitely. This is
  especially significant given that the same flat, unsegmented network
  (10.10.0.0/16) already noted throughout this assessment gives any
  compromised device or credential a direct path to the rest of the
  environment.
Evidence: The Control Summary Matrix (Task 4) has no entries anywhere in
  the Compensating column. The IT Asset List (Task 0 source material)
  flags the MRI scanner's Windows XP OS as "CRITICAL" in Marcus's own
  notes; Artifact 2 confirms SSH password authentication is still
  enabled on all Linux servers except ehr-srv-01.
```

---

## Pattern Analysis

Looking at the gaps as a whole, MedDefense's posture is **prevention-oriented in intent but shallow in practice, and almost entirely absent in response capability**. The controls that exist skew heavily toward Preventive and, to a lesser extent, passive Detective technical measures (firewall rules, SSH hardening on one server, antivirus on one platform), but every detective control identified is siloed and unalerted, and the Corrective, Compensating, and Deterrent functions are nearly empty across all three categories. This implies that if an incident bypasses MedDefense's preventive controls, which has already happened twice on the same server, the organization has very limited ability to detect it quickly (discovery has so far depended on accidents, like a sysadmin manually checking a slow server, rather than design) and no tested, documented way to respond or recover in a structured, timely manner.
