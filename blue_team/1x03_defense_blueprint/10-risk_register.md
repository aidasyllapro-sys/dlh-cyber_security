# MedDefense Health Systems: The Risk Register

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** Every deliverable of Projects 0x00, 1x01, and 1x02, plus the ALE calculations (Task 5, Task 6), cost-benefit evaluations (Task 7), and governance roles (Task 4) built in this project **Purpose:** This is not a summary document. It is the living instrument James Chen opens when the Board asks what keeps him up at night, the single source of truth for MedDefense's risk posture, tracked from identification through treatment to ongoing monitoring.

**Scales used throughout this register:**

**Likelihood (1-5):** 1 = Rare, unlikely within 5 years. 2 = Unlikely, possible within 3-5 years. 3 = Possible, expected roughly once every 1-3 years. 4 = Likely, expected annually or more often. 5 = Almost Certain, expected multiple times per year or already recurring.

**Impact (1-5):** 1 = Negligible, under $10,000, no patient or regulatory impact. 2 = Minor, $10,000-$100,000, limited operational disruption. 3 = Moderate, $100,000-$1,000,000, regulatory notification likely required. 4 = Major, $1,000,000-$5,000,000, significant patient, financial, or regulatory impact. 5 = Catastrophic, over $5,000,000, direct patient safety risk or existential regulatory/business consequence.

---

yaml

```yaml
Risk ID: RISK-001
Risk Description: A ransomware group gains network access via the
  FortiGate VPN and, given the flat network, encrypts and exfiltrates
  data from the EHR system and billing server together in a single
  campaign.
Risk Category: Operational
Threat Source: Ransomware Groups (1x01, #1-ranked threat actor)
Vulnerability: Findings 001, 003, 031 (1x02)
Affected Asset(s): FortiGate 100F, EHR System (ehr-srv-01, ehr-db-01),
  billing-srv-01 (0x00 Asset Registry)
Likelihood: 3, Possible (ARO 0.3, roughly once every 3.3 years, Task 6)
Impact: 5, Catastrophic (AV $9,548,000, Task 6)
Inherent Risk Score: 3 x 5 = 15
ALE: $2,864,400 (Task 6)
Risk Owner: James Chen, Deputy CISO
Treatment Decision: Mitigate
Treatment Justification: The proposed controls return over $1.8 million
  in net annual value against a $40,000 cost (Task 7), making avoidance
  or acceptance indefensible on the math alone.
Planned Control(s): Network Segmentation, MFA Deployment (Task 7,
  Controls 1 and 2)
Residual Risk: ALE reduced to an estimated $1,002,540 with segmentation
  alone, and further reduced by MFA's independent contribution; residual
  Inherent Risk Score estimated at 2 x 4 = 8 once both controls are
  fully deployed
KRI: Number of hosts able to reach both ehr-db-01 and billing-srv-01
  from a single network segment (target: 0 once segmentation is live);
  failed VPN authentication attempts per day
Review Date: Monthly, next review in 30 days, given this is the
  program's highest-priority risk
```

yaml

```yaml
Risk ID: RISK-002
Risk Description: An actor with any level of network access queries or
  exfiltrates the complete patient database directly, since ehr-db-01
  accepts connections from the entire internal network rather than only
  the application server.
Risk Category: Compliance
Threat Source: All six actor types profiled in 1x01, given this
  exposure requires no specific technique to reach
Vulnerability: Finding 003 (1x02)
Affected Asset(s): ehr-db-01 (0x00 Asset Registry, #1-ranked Critical
  Asset)
Likelihood: 4, Likely (ARO 0.45, adjusted upward from sector baseline
  given MedDefense's confirmed compounding weaknesses, Task 6)
Impact: 5, Catastrophic (AV $9,075,000, Task 6)
Inherent Risk Score: 4 x 5 = 20
ALE: $4,083,750 (Task 6), the highest single ALE figure in this
  program's entire body of work
Risk Owner: James Chen, Deputy CISO
Treatment Decision: Mitigate
Treatment Justification: The proposed control costs $500 and returns
  over $3.2 million in net annual value (Task 7), the single highest
  return on investment identified anywhere in this program.
Planned Control(s): pg_hba.conf restriction to ehr-srv-01 only, plus
  host-based firewall rule (1x02, Task 19; Task 7, Control referenced
  within Control 1's broader segmentation effort)
Residual Risk: ALE reduced to an estimated $816,750 (Task 6); residual
  Inherent Risk Score estimated at 4 x 3 = 12, since the likelihood of
  attempted access does not change, only what an attacker can reach
KRI: Number of distinct source hosts successfully connecting to port
  5432 on ehr-db-01 per day (target: 1, ehr-srv-01 only)
Review Date: Monthly, next review in 30 days
```

yaml

```yaml
Risk ID: RISK-003
Risk Description: Ransomware gains initial access through billing-
  srv-01's unpatched Apache vulnerability, the confirmed Step 1 of Kill
  Chain 1, on a server already compromised twice in MedDefense's
  history.
Risk Category: Financial
Threat Source: Ransomware Groups, Kill Chain 1 (1x01)
Vulnerability: Findings 001, 002 (1x02)
Affected Asset(s): billing-srv-01 (0x00 Asset Registry)
Likelihood: 3, Possible (ARO 0.29, Task 6)
Impact: 3, Moderate (AV $473,000, Task 6)
Inherent Risk Score: 3 x 3 = 9
ALE: $137,170 (Task 6)
Risk Owner: Sarah Park, IT Director (execution), James Chen (program
  accountability, per Task 4 RACI)
Treatment Decision: Mitigate
Treatment Justification: A $5,000 patch closes the exact, already-
  exploited entry point behind two prior compromises on this host,
  returning nearly $85,000 in net annual value (Task 6, Task 7).
Planned Control(s): Apache upgrade to 2.4.52 or later (1x02, Task 19)
Residual Risk: ALE reduced to an estimated $47,300 (Task 6); residual
  Inherent Risk Score estimated at 2 x 3 = 6
KRI: Apache version drift from current patched baseline; count of
  unpatched CVEs affecting billing-srv-01 in the monthly vulnerability
  scan
Review Date: Quarterly, next review in 90 days
```

yaml

```yaml
Risk ID: RISK-004
Risk Description: Ransomware destroys or encrypts NAS-01 during an
  active incident, removing MedDefense's ability to recover without a
  full rebuild, the documented, doctrinal target of this program's
  highest-priority threat actor.
Risk Category: Operational
Threat Source: Ransomware Groups, Kill Chain 1 (1x01, Task 2's own
  documented affiliate playbook)
Vulnerability: Finding 015, plus CVE-2024-10441 discovered through
  OSINT research (1x02, Task 9)
Affected Asset(s): NAS-01 (0x00 Asset Registry, #5-ranked Critical
  Asset)
Likelihood: 3, Possible (ARO 0.25, Task 6)
Impact: 4, Major (AV $1,090,000, Task 6)
Inherent Risk Score: 3 x 4 = 12
ALE: $272,500 (Task 6)
Risk Owner: Sarah Park, IT Director
Treatment Decision: Mitigate
Treatment Justification: A $13,000 combined patch-and-isolation
  investment returns over $218,000 in net annual value (Task 6), and
  this risk uniquely amplifies every other risk in this register by
  removing the organization's recovery capability.
Planned Control(s): CVE-2024-10441 patch plus isolated/immutable backup
  copy (Task 6); Offsite Backup Replication (Task 7, Control 4) as a
  stronger complementary or alternative implementation
Residual Risk: ALE reduced to an estimated $27,250-$40,875 depending on
  which control path is chosen (Task 6, Task 7); residual Inherent Risk
  Score estimated at 3 x 2 = 6
KRI: Days since last verified, successful restore test from an isolated
  or offsite copy; NAS-01 DSM patch currency against Synology's latest
  advisory
Review Date: Monthly, next review in 30 days, given this risk's
  amplifying effect on the rest of this register
```

yaml

```yaml
Risk ID: RISK-005
Risk Description: An opportunistic attacker exploits default
  credentials and flat network access on the BD Alaris infusion pump
  fleet, ranging from a denial-of-service event to a genuine patient
  safety incident.
Risk Category: Operational
Threat Source: Unskilled/Opportunistic Attacker (1x01)
Vulnerability: Finding 010 (1x02)
Affected Asset(s): BD Alaris infusion pumps (0x00 Asset Registry,
  #3-ranked Critical Asset)
Likelihood: 2, Unlikely (blended across the DoS and patient-safety
  sub-scenarios, ARO 0.1 and 0.02 respectively, Task 6)
Impact: 4, Major (patient safety dimension weighted above the AV alone,
  Task 6)
Inherent Risk Score: 2 x 4 = 8
ALE: $70,000 combined (Task 6)
Risk Owner: Relevant Department Head (Radiology/Clinical Engineering,
  as Data Owner per Task 4) for clinical impact; Sarah Park for network
  execution
Treatment Decision: Mitigate
Treatment Justification: Credential changes cost effectively nothing
  and network isolation returns nearly $50,000 in net annual value
  against a direct patient-safety risk (Task 6).
Planned Control(s): Default credential change fleet-wide, network
  isolation (1x02, Task 20; Task 6)
Residual Risk: ALE reduced to an estimated $17,000 (Task 6); residual
  Inherent Risk Score estimated at 1 x 3 = 3
KRI: Number of scanned pumps still carrying default credentials
  (target: 0); number of medical devices reachable from outside the
  designated clinical VLAN
Review Date: Quarterly, next review in 90 days
```

yaml

```yaml
Risk ID: RISK-006
Risk Description: WS-RAD-01, the MRI workstation, is compromised via
  any of three independently weaponized, CISA KEV-listed vulnerabilities
  on its permanently unpatchable Windows XP operating system, halting
  diagnostic imaging and risking falsified clinical data.
Risk Category: Operational
Threat Source: Unskilled/Opportunistic Attacker and Ransomware Groups
  (both confirmed exploitation classes, 1x01)
Vulnerability: Finding 004 (1x02)
Affected Asset(s): WS-RAD-01 (0x00 Asset Registry, #4-ranked Critical
  Asset)
Likelihood: 4, Likely (three confirmed weaponized exploits, one added to
  CISA KEV only weeks before the 1x02 assessment, signaling renewed
  active exploitation interest, Task 4/12 of 1x02)
Impact: 5, Catastrophic (patient-safety-critical Availability and
  Integrity, 0x00 Criticality Assessment)
Inherent Risk Score: 4 x 5 = 20, tied with RISK-002 for the highest
  inherent score in this register
ALE: Not separately quantified in Task 5 or Task 6; qualitatively
  assessed as Critical given three independently weaponized, KEV-listed
  CVEs on a Top-5 Critical Asset with no possible patch (1x02, Task 10).
  This gap is stated directly rather than papered over with an
  unsupported number.
Risk Owner: Relevant Department Head (Radiology, as Data Owner per Task
  4), with James Chen accountable for the compensating control program
Treatment Decision: Mitigate
Treatment Justification: A patch is permanently impossible given this
  system's end-of-life status (1x02, Task 12); compensating network
  controls are the only available treatment and are already the
  top-funded item in this program's remediation strategy.
Planned Control(s): Network Segmentation (Task 7, Control 1), dedicated
  medical device VLAN restricting traffic to the PACS server only (0x00,
  Task 6 compensating controls, still not yet implemented)
Residual Risk: Segmentation contains but does not eliminate this risk,
  since an attacker already positioned on the restricted VLAN retains
  access; residual risk remains elevated relative to every other risk in
  this register given the underlying vulnerability can never be closed
KRI: New CISA KEV catalog additions affecting Windows XP-era SMB/RDP
  components; days since the last validation test confirming this device
  is unreachable from outside its designated VLAN
Review Date: Monthly, next review in 30 days, given this risk cannot be
  permanently closed and requires the tightest ongoing monitoring in
  this register
```

yaml

```yaml
Risk ID: RISK-007
Risk Description: A negligent employee, using unrestricted USB access
  or a shared account on one of approximately 280 unmonitored clinical
  workstations, causes an inadvertent patient data exposure.
Risk Category: Compliance
Threat Source: Insider (Negligent), 1x01 Task 3
Vulnerability: No specific 1x02 scan finding; tied to GAP-023/GAP-024
  (0x00, no USB restriction, no DLP)
Affected Asset(s): Approximately 280 clinical workstations with EHR
  access (0x00 Asset Registry)
Likelihood: 5, Almost Certain (ARO 2.5, more than twice per year, Task 5
  Scenario 3)
Impact: 2, Minor (average incident cost $120,000, Task 5)
Inherent Risk Score: 5 x 2 = 10
ALE: $300,000 (Task 5, Scenario 3)
Risk Owner: Sarah Park, IT Director (technical control), Department
  Heads (staff accountability, per Task 4 RACI)
Treatment Decision: Mitigate
Treatment Justification: A single Group Policy deployment closes the
  primary technical enabler of this risk at low cost relative to its
  $300,000 annual expected cost.
Planned Control(s): USB mass storage GPO restriction (1x02, Task 20)
Residual Risk: Not separately recalculated with a formal control cost
  in Task 6 or Task 7; qualitatively expected to reduce ARO
  substantially once the technical enabler is closed, though the human
  behavior component of this risk means it cannot be fully eliminated by
  a technical control alone
KRI: Number of USB mass storage connection events on clinical
  workstations per month; security awareness training completion rate
  by site (currently as low as 58% at one location, 1x01, Task 4)
Review Date: Quarterly, next review in 90 days
```

yaml

```yaml
Risk ID: RISK-008
Risk Description: An incident of any kind occurs and MedDefense's
  response is delayed or mishandled due to the absence of a documented,
  tested incident response plan, compounding regulatory and financial
  exposure beyond the initial incident itself.
Risk Category: Compliance
Threat Source: All actor types benefit equally, since this risk
  determines how much damage any successful compromise accumulates
  before MedDefense responds, independent of which actor succeeded first
Vulnerability: No specific 1x02 scan finding; this is GAP-015 (0x00), a
  process gap rather than a technical one
Affected Asset(s): Organization-wide
Likelihood: 4, Likely (some incident requiring response is expected
  given the other nine risks in this register)
Impact: 4, Major (regulatory notification delay, uncontrolled scope
  determination, and the demonstrated real-world consequence of the
  billing-srv-01 cryptominer being misdiagnosed as a hardware issue,
  0x00, Task 2)
Inherent Risk Score: 4 x 4 = 16
ALE: Not separately quantified; this risk functions as an amplifier
  across every other risk in this register rather than an independently
  scored event, consistent with how this program has treated GAP-015
  throughout (1x03, Task 3)
Risk Owner: James Chen, Deputy CISO (Responsible for drafting, per Task
  4 RACI), CEO (Accountable for final approval)
Treatment Decision: Mitigate
Treatment Justification: Building and exercising an incident response
  plan is primarily a documentation and process exercise, achievable
  within this program's 6-month timeframe without significant capital
  cost (1x03, Task 1).
Planned Control(s): Draft and formally exercise a documented incident
  response plan (1x03, Task 1's own 6-month target for the Respond
  Function)
Residual Risk: Not separately quantified; qualitatively expected to
  reduce the compounding/amplifying effect this gap currently has across
  every other risk in this register once a tested plan exists
KRI: Days since the last incident response tabletop exercise; time-to-
  detect and time-to-contain measured against any real or simulated
  incident
Review Date: Quarterly, next review in 90 days
```

yaml

```yaml
Risk ID: RISK-009
Risk Description: A third-party vendor with direct access to the EHR
  environment is compromised, and that vendor's own legitimate access is
  used to reach MedDefense's systems without ever breaching MedDefense's
  own perimeter.
Risk Category: Strategic
Threat Source: Organized Crime, via a compromised vendor (1x01, Scenario
  3, "The Trusted Vendor Path")
Vulnerability: No specific 1x02 scan finding; tied to GAP-026 (1x01,
  Task 15), no dedicated vendor-access segmentation
Affected Asset(s): ehr-srv-01, via MedTech Solutions' maintenance access
  (1x01, Task 5, Supply Chain Question)
Likelihood: 2, Unlikely (no confirmed incident of this type at
  MedDefense specifically, though the underlying access pathway is real
  and persistent, 1x01, Task 5)
Impact: 4, Major (direct, high-privilege access to the #1 Critical
  Asset, with a materially longer expected time-to-detection since the
  access itself appears entirely legitimate, 1x01, Task 14)
Inherent Risk Score: 2 x 4 = 8
ALE: Not separately quantified in Task 5 or Task 6; this gap in the
  program's own quantitative work is stated directly rather than
  invented
Risk Owner: James Chen, Deputy CISO
Treatment Decision: Mitigate
Treatment Justification: A dedicated vendor jump-host with MFA and
  session logging is the single control recommendation this program has
  made consistently regarding vendor access since 1x01, Task 5.
Planned Control(s): Dedicated vendor-access jump-host requiring MFA and
  full session logging (1x01, Task 5)
Residual Risk: Not separately recalculated with a formal control cost in
  Task 6 or Task 7; qualitatively expected to substantially reduce this
  risk's likelihood once vendor sessions are isolated and logged
  independently of MedDefense's own network
KRI: Number of vendors with standing remote access lacking a signed
  security addendum; number of active vendor remote sessions without MFA
  enforced
Review Date: Quarterly, next review in 90 days
```

yaml

```yaml
Risk ID: RISK-010
Risk Description: Westside Clinic's consumer-grade router, the sole
  perimeter device for that site and the termination point for its
  site-to-site VPN, is compromised, granting an attacker a direct tunnel
  into Central's server network.
Risk Category: Operational
Threat Source: Ransomware Groups and Unskilled/Opportunistic Attacker
  (1x01)
Vulnerability: Finding 014 (1x02)
Affected Asset(s): Westside Clinic perimeter router, and by extension,
  Central's server network (0x00 Asset Registry, GAP-021)
Likelihood: 3, Possible (ARO 0.15, Task 7, Control 6)
Impact: 4, Major (AV $3,000,000, a partial-compromise scenario relative
  to the full aggregate exposure in RISK-001, Task 7)
Inherent Risk Score: 3 x 4 = 12
ALE: $450,000 (Task 7, Control 6)
Risk Owner: Sarah Park, IT Director
Treatment Decision: Mitigate
Treatment Justification: A $1,800 annual cost (amortized hardware plus
  support) returns over $358,000 in net annual value (Task 7), one of
  the highest return ratios of any control in this program.
Planned Control(s): Dedicated enterprise-grade firewall replacing the
  consumer router (Task 7, Control 6)
Residual Risk: ALE reduced to an estimated $90,000 (Task 7); residual
  Inherent Risk Score estimated at 2 x 3 = 6
KRI: Firmware age of Westside's perimeter device; number of
  administrative logins to the device from IP addresses outside the
  approved management range
Review Date: Quarterly, next review in 90 days
```

---

## Risk Register Governance Note

This register is maintained by James Chen as Deputy CISO, with the Security Analyst responsible for updating individual entries as remediation work closes, new findings emerge, or ALE figures are recalculated, consistent with the RACI structure already established in this program (Task 4). The full register is formally reviewed monthly for the four highest-inherent-score risks (RISK-001, RISK-002, RISK-004, and RISK-006, each carrying either the program's highest financial exposure or an unpatchable, ongoing vulnerability) and quarterly for the remaining six, a cadence that concentrates the tightest oversight on the risks this program's own analysis has repeatedly identified as most consequential. An out-of-cycle review is triggered by any of the following: a new CISA KEV catalog addition affecting software or hardware confirmed present in MedDefense's asset inventory, a completed remediation that changes a risk's residual score, a new OSINT-discovered vulnerability of the kind Task 9 of Project 1x02 demonstrated can appear outside the normal scan cycle, or any actual security incident regardless of severity. When a Key Risk Indicator breaches its stated threshold, for example a scanned medical device found still carrying default credentials after RISK-005's control is marked complete, that breach is escalated to James Chen within 48 hours, the risk's Likelihood and residual scores are reassessed immediately rather than waiting for the next scheduled review, and if the reassessment materially changes the risk's priority, it is brought to the CEO for a renewed treatment decision at the next available governance touchpoint, consistent with the risk-acceptance authority already defined in this program's Governance Architecture (Task 4).
