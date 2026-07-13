# MedDefense Health Systems: Prioritized gap analysis

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO (for Board presentation) **Source material:** Asset Criticality Assessment (Task 8), Data Map (Task 9), Complete Control Matrix (Task 10), Shadow IT Findings (Task 11) **Purpose:** Cross-reference asset criticality, data sensitivity, and control coverage to produce a single, prioritized list of security gaps the Board can act on.

**Prioritization rules applied:**

- **Critical:** Gap affects a Critical-rated asset or Restricted data AND has no detective or corrective control
- **High:** Gap affects a High-rated asset or Confidential data AND has incomplete control coverage
- **Medium:** Gap affects a Medium-rated asset OR has partial controls that reduce but do not eliminate risk
- **Low:** Gap affects a Low-rated asset AND has partial compensating measures

---

## Gap list

```
Gap ID: GAP-001
Title: Medical IoT (Infusion Pumps) has zero security control coverage of any kind
Affected Asset(s): BD Alaris Infusion Pumps, ~120 units (Task 7, A-028) as medical IoT
  category, rated Critical (Task 8)
Data at Risk: Medical Device / Vital Signs & Infusion Data, Restricted (Task 9)
Current Control Status: Per the Task 10 Control Coverage Map, this asset has NO
  Preventive, Detective, Corrective, or Compensating control of any category.
What is Missing: Every function, Technical Preventive (network segmentation),
  Technical Detective (monitoring for anomalous device behavior), Technical
  Corrective (device configuration is explicitly excluded from backup, per Task 5)
Risk Level: Critical
Risk Justification: Affects a Critical-rated asset holding Restricted data, with
  no detective or corrective control whatsoever, meets the Critical rule exactly.
  This is compounded by a vendor-confirmed CVE (firmware v12.1.2) with an
  18-month-old, unactioned isolation recommendation (Task 7/8).
Potential Impact: A falsified or manipulated dosage setting is not a data
  incident. It is an immediate, direct threat to patient safety. This is the
  single most severe realistic scenario in the entire assessment.
```

```
Gap ID: GAP-002
Title: MRI workstation remains fully exposed and proposed compensating controls
  have not been implemented
Affected Asset(s): MRI Scanner & WS-RAD-01 (Task 7, A-019/A-032) - PACS/Diagnostic
  Imaging category, rated Critical (Task 8)
Data at Risk: Medical Imaging Data — Restricted (Task 9)
Current Control Status: A full compensating-control strategy (P-001 through
  P-004) was designed in Task 6, but per the Task 10 registry, none of these
  controls have been implemented. Current coverage is effectively zero.
What is Missing: Technical Compensating (network micro-segmentation),
  Technical Detective (IDS/IPS at the segment boundary), Physical Compensating
  (console access restriction), Administrative Compensating (formal risk
  acceptance/runbook)
Risk Level: Critical
Risk Justification: Affects a Critical-rated asset holding Restricted data with
  no detective or corrective control currently in place, matching the Critical
  rule. The gap is made worse by the underlying condition: an OS unpatched
  since 2014 on the same flat network as every other system.
Potential Impact: Supports approximately 45 studies per day; a compromise or
  disruption directly halts diagnostic imaging capability, and the device's
  network position (same VLAN as general workstations) makes it a plausible
  entry point to the wider network as well as a target in its own right.
```

```
Gap ID: GAP-003
Title: EHR database is reachable from the entire internal network, bypassing
  application-layer controls entirely
Affected Asset(s): ehr-db-01 (Task 7, A-002), part of the EHR System, rated
  Critical (Task 8)
Data at Risk: Patient Medical Records - Restricted (Task 9)
Current Control Status: SSH key-only authentication exists on ehr-srv-01 (the
  application server) but not on the database tier; the perimeter firewall's
  default-deny policy (C-002) governs external traffic only. PostgreSQL
  (port 5432) is confirmed reachable from the entire internal network
  (Task 0/7/9).
What is Missing: Technical Preventive (network-level access restriction
  limiting database connections to ehr-srv-01 only); no Detective control
  monitors direct connection attempts to the database independent of the
  application layer.
Risk Level: Critical
Risk Justification: Affects a Critical-rated asset holding Restricted data,
  and, critically, this specific exposure has no detective control watching
  for direct, application-bypassing access to the database, meeting the
  Critical rule.
Potential Impact: Any actor with a foothold anywhere on the flat internal
  network, including through any of the other gaps in this list, can
  connect directly to the full patient database, bypassing whatever
  access-control weaknesses exist or are ever fixed at the application layer
  (the same layer where Incident B's IDOR vulnerability was found). This is a
  mass PHI exfiltration risk, not an incremental one.
```

```
Gap ID: GAP-004
Title: No centralized log correlation or alerting exists anywhere in the
  organization
Affected Asset(s): Organization-wide — directly implicates every Critical-rated
  asset (EHR System, ad-dc-01, Billing, Medical IoT, MRI, Backup Infrastructure
  — Task 8)
Data at Risk: All Restricted-classification data categories (Patient Medical
  Records, Medical Imaging Data, Financial/Billing Data, Medical Device Data)
  and the Restricted-classification System Credentials category (Task 9)
Current Control Status: Multiple detective controls exist in isolation
  (C-003, C-006, C-014, C-015, C-016 — Task 10), but every one is rated Weak:
  none are forwarded, correlated, or alerted on.
What is Missing: Technical Detective (a centralized log management/alerting
  capability, a SIEM or equivalent), first identified as Gap G-001 in Task 5
  and confirmed structurally in the Task 10 Control Summary Matrix (every
  Detective cell across all three categories averages at or near "Weak").
Risk Level: Critical
Risk Justification: Affects every Critical-rated asset and multiple Restricted
  data categories simultaneously; the existing "detective" controls are
  detective in name only, since none of them function as an actual detection
  mechanism absent a human manually reviewing logs "when something breaks"
  (Task 4, Artifact 8). This is functionally equivalent to having no detective
  control at all.
Potential Impact: This is not a theoretical gap — it is the exact condition
  that allowed the cryptominer on billing-srv-01 to run undetected (Task 2).
  Without remediation, any future compromise of any Critical asset is likely
  to be discovered by accident, not by design.
```

```
Gap ID: GAP-005
Title: No antivirus/endpoint protection exists on any server — Windows or Linux
Affected Asset(s): All servers, including ehr-srv-01, ehr-db-01, billing-srv-01
  (Critical, Task 8), ad-dc-01 (Critical, Task 8), file-srv-01, pacs-srv-01
Data at Risk: Patient Medical Records, Financial/Billing Data — both Restricted
  (Task 9)
Current Control Status: C-009 (Sophos) exists but explicitly excludes all
  Windows and Linux servers (Task 4/10, rated Weak).
What is Missing: Technical Preventive (server-class endpoint protection/EDR)
Risk Level: Critical
Risk Justification: Affects multiple Critical-rated assets holding Restricted
  data, and this is not a hypothetical exposure — it has already been
  exploited once (the cryptominer on billing-srv-01, Task 2) and went
  undetected by any existing control, satisfying the "no detective or
  corrective control" condition in practice, even though a detective control
  nominally exists elsewhere in the environment.
Potential Impact: Repeat compromise of any server-class Critical asset,
  following the exact pattern already demonstrated — with no automated
  mechanism to prevent, detect, or contain it before it is found by accident.
```

```
Gap ID: GAP-006
Title: The organization's only backup infrastructure is a single point of
  failure with no offsite or immutable copy
Affected Asset(s): NAS-01 / backup-srv-01 (Task 7, A-009/A-010) — Backup &
  Recovery Infrastructure category, rated Critical (Task 8, ranked #5 in the
  Top 5 Critical Assets)
Data at Risk: Every backed-up Restricted category — Patient Medical Records,
  Financial/Billing Data, and (via ad-dc-01) System Credentials
Current Control Status: C-010 (nightly Veeam backup) exists but is rated Weak
  (Task 10) — the NAS is co-located in the same room, rack row, and network as
  the systems it protects, no offsite/cloud copy exists, and a full disaster
  recovery test has never been performed.
What is Missing: Technical Corrective (genuine disaster-recovery capability, 
  an offsite or immutable backup copy independent of the primary environment)
Risk Level: Critical
Risk Justification: Affects a Critical-rated asset holding Restricted data,
  and for the specific scenario this control exists to address — a
  site-level or network-propagating incident — the corrective control
  effectively does not function, since source and backup would very likely
  be lost together.
Potential Impact: In a fire, flood, or ransomware event that spreads
  laterally across the flat network (a demonstrated risk, given the January
  ransomware incident), MedDefense could lose both its production systems and
  its only backup simultaneously, with no verified path back to operations.
```

```
Gap ID: GAP-007
Title: The server room and network closet, housing or controlling access to
  nearly every Critical asset, have no detective physical control at all
Affected Asset(s): Server room (houses ad-dc-01, ehr-srv-01, ehr-db-01,
  billing-srv-01, NAS-01 — all Critical per Task 8); network closet (controls
  core switching)
Data at Risk: System Credentials — Restricted (posted openly in the closet,
  per Task 3/9); indirectly, every Restricted data category, since physical
  access here enables compromise of everything else
Current Control Status: C-017 (badge access, Weak) and C-012 (CCTV cameras,
  Weak) exist in the Control Matrix, but C-012 explicitly does not cover
  either of these two rooms (Task 4/10).
What is Missing: Physical Detective (no camera or monitoring of any kind in
  either room) and effective Physical Preventive (the badge control that does
  exist is undifferentiated — the same badge every employee receives)
Risk Level: Critical
Risk Justification: These two physical locations directly protect multiple
  Critical-rated assets and Restricted-classification System Credentials, and
  there is zero detective control for either room, meeting the Critical rule
  precisely.
Potential Impact: Undetected physical tampering, theft, or credential
  compromise (the posted switch credentials, Task 3 Observation 2) could
  enable an attacker to reconfigure or monitor the entire internal network,
  with no camera footage or access log to ever establish who was responsible.
```

```
Gap ID: GAP-008
Title: Physician iPads have no device management, encryption enforcement, or
  remote-wipe capability
Affected Asset(s): ~25 physician iPads (Task 7, A-021), Clinical Endpoints
  category, rated High (Task 8)
Data at Risk: Patient Medical Records accessed during rounds — Restricted
  (Task 9)
Current Control Status: No MDM/EMM solution exists; Sophos explicitly excludes
  these devices (Task 4/7).
What is Missing: Technical Preventive (Mobile Device Management, enforced
  encryption, passcode policy, and remote wipe)
Risk Level: High
Risk Justification: Affects a High-rated asset category with incomplete
  control coverage. No management layer exists for this device class at
  all, meeting the High rule.
Potential Impact: A lost or stolen iPad with no remote-wipe capability and no
  confirmed encryption enforcement represents an uncontained PHI exposure with
  no way for MedDefense to remediate remotely.
```

```
Gap ID: GAP-009
Title: No administrative process exists to verify that security policies are
  actually followed in practice
Affected Asset(s): Organization-wide — most directly the Identity & Network
  Core Infrastructure category (High/Critical per Task 8) via unenforced SSH
  and credential-handling standards
Data at Risk: System Credentials — Restricted (Task 9)
Current Control Status: Zero controls exist anywhere in the Administrative
  Detective cell of the Control Summary Matrix (Task 10, Part 2).
What is Missing: Administrative Detective (a periodic compliance/access
  review process)
Risk Level: High
Risk Justification: Affects Restricted-classification credential handling
  organization-wide with incomplete (in fact, entirely absent) governance
  coverage, meeting the High rule. This is a structural/procedural gap that
  perpetuates several of the other gaps in this list, rather than a single
  direct technical exposure.
Potential Impact: Continued, undetected divergence between stated policy and
  actual practice — already demonstrated by the SSH key-only migration
  stalling after a single server, and the shared PACS login that was reported
  but never remediated (Task 0).
```

```
Gap ID: GAP-010
Title: Multiple unmanaged, undocumented devices operate on the same network
  segments as Critical assets
Affected Asset(s): UNKNOWN-01 (Task 7, A-012), unidentified Westside device
  (Task 7, A-024), and the three shadow systems identified in Task 11
  (Dr. Patel's NAS, Marketing's Google Drive, the Raspberry Pi) — none
  formally criticality-rated, but UNKNOWN-01 sits on the same subnet as
  ad-dc-01 and ehr-db-01 (both Critical, Task 8)
Data at Risk: Unknown by definition — this lack of visibility is itself the
  core problem; the Raspberry Pi in particular may have had visibility into
  network traffic carrying Restricted data (Task 11)
Current Control Status: None — these assets are, by definition, outside every
  control in the Task 10 Control Matrix.
What is Missing: Every function — Preventive, Detective, Corrective, and
  Compensating are all absent, since these assets were not even inventoried
  until Tasks 7 and 11.
Risk Level: Critical
Risk Justification: While these specific devices are not individually
  criticality-rated, at least one (UNKNOWN-01) sits directly adjacent to
  Critical-rated assets with zero control coverage of any kind, meeting the
  Critical rule through proximity and total absence of protection.
Potential Impact: These devices represent a plausible, already-present
  foothold of unknown origin and duration on the same network as the
  organization's most sensitive systems. The precautionary assumption from
  Task 8 (treat as maximum risk until investigated) still applies and has not
  yet been resolved.
```

```
Gap ID: GAP-011
Title: Employee HR records have no documented storage system, and the VPN
  carrying them has never been audited
Affected Asset(s): Employee HR system (location undocumented — Task 9) —
  falls under Administrative Endpoints & Corporate Data Services, rated High
  (Task 8)
Data at Risk: Employee HR Records — Confidential (Task 9)
Current Control Status: General organization-wide password policy; HQ-to-
  Central site-to-site VPN carries this traffic, but its access control lists
  have never been audited (Task 0).
What is Missing: Administrative Preventive (a documented system of record
  with clear ownership) and Technical Preventive (a verified, audited VPN
  ACL configuration)
Risk Level: High
Risk Justification: Affects a High-rated asset category holding Confidential
  data with incomplete control coverage. MedDefense cannot currently confirm
  where this data lives or that its transport path is properly restricted,
  meeting the High rule.
Potential Impact: Potential unauthorized internal access to employee
  records via an unverified VPN path, compounded by an inability to even
  confirm the scope of a breach given the lack of a documented system of
  record.
```

```
Gap ID: GAP-012
Title: Security awareness training exists but is incomplete and untested
  against real-world scenarios
Affected Asset(s): Entire workforce — touches every endpoint category
  (Clinical and Administrative, both rated High, Task 8)
Data at Risk: All data categories, indirectly — most incidents in this
  project trace back to a human action or inaction (Incident B's exploited
  access control, the unattended EHR session in Task 3)
Current Control Status: C-013 (mandatory annual training) exists but is rated
  Weak (Task 10) — completion ranges from 58% (Westside) to 94% (HQ), with no
  phishing simulations and no PHI-specific or role-specific content.
What is Missing: A more complete Administrative Preventive control (full,
  role-specific completion) and an Administrative Detective control (phishing
  simulation to measure actual susceptibility, which does not currently
  exist in any form)
Risk Level: Medium
Risk Justification: This is a partial control that reduces but does not
  eliminate risk (training exists and does have some completion and content,
  distinguishing it from the total absence seen in GAP-001 through GAP-010) meeting the Medium rule.
Potential Impact: Elevated susceptibility to social engineering and phishing,
  most acutely at Westside, which, per the physical assessment (Task 3) and
  environment summary (Task 0), already has the weakest physical and network
  security posture of the three sites.
```

```
Gap ID: GAP-013
Title: print-srv-01 is an unpatched, end-of-life system with no backup, but
  limited direct clinical impact
Affected Asset(s): print-srv-01 (Task 7, A-008) is not part of any Critical or
  High-rated category in Task 8; printing infrastructure is not clinical- or
  life-safety-critical
Data at Risk: Print job metadata — generally Internal classification, though
  it is worth noting some print jobs (e.g., patient wristband labels or
  prescription printouts) could occasionally carry Restricted-level PHI in
  transit to the printer, a nuance not independently confirmed by any source
  in this project
Current Control Status: Domain-enforced password policy and account lockout
  (C-007/C-008) still apply since the server is presumably domain-joined; no
  backup (C-010 excludes it) and no antivirus (C-009 excludes all servers).
What is Missing: Technical Corrective (no backup) and Technical Preventive
  (the underlying OS has been end-of-life since October 2023)
Risk Level: Low
Risk Justification: Affects a Low-criticality asset, and partial
  compensating protection still exists via organization-wide identity
  controls (password policy, lockout), even though backup and endpoint
  protection are absent, meeting the Low rule.
Potential Impact: Direct impact of a compromise is limited (print service
  disruption), but an unpatched, unmonitored EOL server on the same flat
  network as everything else remains a plausible secondary pivot point,
  which keeps this from being a negligible finding entirely.
```

---

## Gap Distribution Summary

### Gaps by Risk level

|Risk Level|Count|Gap IDs|
|---|---|---|
|Critical|8|GAP-001, GAP-002, GAP-003, GAP-004, GAP-005, GAP-006, GAP-007, GAP-010|
|High|3|GAP-008, GAP-009, GAP-011|
|Medium|1|GAP-012|
|Low|1|GAP-013|
|**Total**|**13**||

The distribution is heavily weighted toward Critical (8 of 13 gaps, ~62%). This is not an artifact of scoring generosity. It directly reflects the Task 8 finding that the majority of MedDefense's asset categories (EHR, PACS/Imaging, Billing, Identity & Network Core, Medical IoT, Backup Infrastructure) are themselves rated Critical, and this gap analysis shows that control coverage has not kept pace with that criticality.

### Asset Categories with the most gaps

Cross-referencing all 13 gaps against the Task 8 asset categories:

1. **Identity & Network Core Infrastructure**: Implicated directly or as a cross-cutting factor in GAP-003, GAP-004, GAP-005, and GAP-009 (4 gaps touch this category, either as the primary subject or as the mechanism by which the gap propagates to other systems).
2. **Medical IoT and PACS/Diagnostic Imaging** (combined as "clinical-device" assets): GAP-001 and GAP-002 represent the two starkest individual findings (zero coverage) in the entire analysis.
3. **Backup & Recovery Infrastructure**: GAP-006 directly, GAP-013 secondarily; notable because this category exists specifically to mitigate the impact of every other gap, yet is itself under-protected.

No single asset category accounts for a majority of gaps in isolation. The pattern is systemic rather than localized to one system, consistent with the flat-network, undifferentiated-access architecture identified throughout this project.

### Concentration by Control Function

Of the 13 gaps identified, **8 (GAP-001, GAP-002, GAP-003, GAP-004, GAP-005, GAP-007, GAP-009, GAP-012)** involve the absence or ineffectiveness of a **Detective** control, across all three categories (Technical, Administrative, and Physical). This is the single most concentrated weakness in this analysis and directly confirms the structural finding first identified in Task 5 (Gap G-001) and carried through the Task 10 Control Summary Matrix, where every Detective cell averaged at or near "Weak." MedDefense's controls, where they exist, are overwhelmingly Preventive in design; the organization currently has very limited ability to detect an incident that bypasses those preventive controls. And, as demonstrated concretely by the billing-srv-01 cryptominer (Task 2), this is not a theoretical weakness but one that has already been exploited.
