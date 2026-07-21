# MedDefense Health Systems: The CIS Controls Audit

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `cis-controls-summary.txt`, cross-referenced against every deliverable of Project 0x00, Project 1x01, and Project 1x02 **Purpose:** Where the NIST CSF mapping (Task 1) established which strategic Functions need attention, this audit scores MedDefense against the 18 concrete, testable CIS Controls that define exactly what to implement to close those gaps.

---

## Control-by-Control Scoring

```
CIS Control 1: Inventory and Control of Enterprise Assets
Score: Partial
Evidence: The 0x00 Asset Registry (Task 7) was the first asset inventory
  MedDefense ever had, and its own reconciliation process directly
  surfaced two previously undocumented shadow IT devices, meaning
  Safeguard 1.1 now exists but Safeguard 1.2 (addressing unauthorized
  assets) is not yet fully executed.
```

```
CIS Control 2: Inventory and Control of Software Assets
Score: Not Implemented
Evidence: Three confirmed end-of-life, unsupported systems (a Windows
  XP MRI workstation, a Windows Server 2012 R2 print server, and an
  Ubuntu 18.04 server with no Extended Security Maintenance enrollment)
  remain in active use, a direct violation of Safeguard 2.2.
```

```
CIS Control 3: Data Protection
Score: Not Implemented
Evidence: Backup data on NAS-01 is stored unencrypted and DICOM medical
  imaging traffic traverses the network in cleartext (1x02, Findings 015
  and 024), with no data classification process evidenced anywhere in
  this program.
```

```
CIS Control 4: Secure Configuration of Enterprise Assets and Software
Score: Not Implemented
Evidence: Misconfiguration was the single largest vulnerability category
  in the 1x02 scan, 12 of 31 findings, including unrestricted database
  binding, LDAP signing left at its insecure default, and unchanged
  default credentials on 100% of scanned medical devices.
```

```
CIS Control 5: Account Management
Score: Not Implemented
Evidence: SSH password authentication remains enabled on the
  organization's most-compromised server (Finding 009), and every
  scanned BD Alaris infusion pump still carries its unchanged default
  administrative credentials, with no evidence anywhere in this program
  of a dormant-account review process.
```

```
CIS Control 6: Access Control Management
Score: Not Implemented
Evidence: GAP-017, no multi-factor authentication anywhere in the
  organization, was identified in 0x00 and confirmed repeatedly across
  all three projects as one of the most consequential open gaps in the
  entire environment.
```

```
CIS Control 7: Continuous Vulnerability Management
Score: Partial
Evidence: Project 1x02 built a complete vulnerability identification,
  prioritization, remediation, and validation process for the first
  time, but its own recommended recurring rescan cadence (Task 23) has
  not yet been executed on more than the single initial cycle.
```

```
CIS Control 8: Audit Log Management
Score: Not Implemented
Evidence: The Lynis self-audit performed in 1x02 (Task 8) confirmed no
  audit daemon and no process accounting on a comparable system, directly
  consistent with GAP-004, independently named one of "The Critical
  Three" gaps across this entire program.
```

```
CIS Control 9: Email and Web Browser Protections
Score: Not Implemented
Evidence: No DNS filtering or managed browser/email protection control
  is evidenced anywhere in this program, and 1x01's Human Vector analysis
  (Task 4) modeled multiple plausible phishing scenarios with no
  confirmed technical mitigation layer standing between the lure and the
  user.
```

```
CIS Control 10: Malware Defenses
Score: Partial
Evidence: Sophos endpoint protection is deployed organization-wide, but
  15 workstations show the agent inactive or not reporting (Finding
  027), and no server-class endpoint protection exists at all, the
  confirmed root cause behind an undetected cryptominer compromise on
  billing-srv-01 (0x00, Task 2).
```

```
CIS Control 11: Data Recovery
Score: Partial
Evidence: Automated backups exist and run on NAS-01, but GAP-006
  confirms this device is co-located with the production systems it
  protects rather than isolated, and 1x02's OSINT research (Task 9)
  subsequently found an unauthenticated remote code execution
  vulnerability on the exact software version this same device runs.
```

```
CIS Control 12: Network Infrastructure Management
Score: Not Implemented
Evidence: GAP-014, the complete absence of network segmentation, was
  independently identified as the single most-referenced weakness across
  the entire three-project program, appearing in 6 of 8 distinct kill
  chains and threat scenarios built in 1x01.
```

```
CIS Control 13: Network Monitoring and Defense
Score: Not Implemented
Evidence: The Lynis self-audit (1x02, Task 8) directly confirmed "no
  IDS/IPS tooling" on a comparable system, and no centralized security
  event alerting capability exists anywhere in MedDefense's environment.
```

```
CIS Control 14: Security Awareness and Skills Training
Score: Partial
Evidence: A training program exists but with inconsistent completion, as
  low as 58% at one site per 1x01's Human Vector analysis (Task 4), and
  this same gap was independently upgraded from Medium to High severity
  in the 1x01 Gap-Threat Correlation (Task 15) once it was confirmed as
  the literal entry point of Kill Chain 1.
```

```
CIS Control 15: Service Provider Management
Score: Partial
Evidence: 1x01's Supply Chain Question (Task 5) assessed 5 vendor
  relationships and their risk levels, but no formal, ongoing
  service-provider management policy existed before or independent of
  that one-time assessment, and dedicated vendor-access segmentation
  remains unimplemented (GAP-026).
```

```
CIS Control 16: Application Software Security
Score: Not Implemented
Evidence: This control has limited direct relevance to MedDefense's
  current environment, since no internally-developed software appears
  anywhere in the 0x00 Asset Registry; the EHR and billing applications
  are both third-party vendor software. Scored Not Implemented for
  completeness, but excluded from the Top 5 priority list below given
  its genuinely low impact on MedDefense's actual risk profile.
```

```
CIS Control 17: Incident Response Management
Score: Not Implemented
Evidence: GAP-015, no incident response plan, was identified as Critical
  in 0x00 and remains unresolved; the organization's one real-world
  incident on record, the billing-srv-01 cryptominer, was misdiagnosed by
  the responding administrator as a hardware issue, direct evidence this
  gap has already produced a real response failure.
```

```
CIS Control 18: Penetration Testing
Score: Not Implemented
Evidence: No evidence anywhere in this three-project program indicates
  MedDefense has ever commissioned a penetration test; SecurePoint's own
  1x02 scan explicitly states no active exploitation was attempted,
  confirming it was a vulnerability scan, not a penetration test.
```

---

## Scorecard Summary

|Score|Count|Controls|
|---|---|---|
|Implemented|0|none|
|Partial|6|1, 7, 10, 11, 14, 15|
|Not Implemented|12|2, 3, 4, 5, 6, 8, 9, 12, 13, 16, 17, 18|
|**Total**|**18**||

Not one of the 18 CIS Controls is currently fully Implemented. This is a stark result, and it should be read alongside, not instead of, the NIST CSF mapping produced in Task 1: the two assessments agree with each other. Where CSF found Identify to be MedDefense's strongest Function, this CIS audit shows the closest matches to that Function (Control 1, asset inventory) also scoring the best result available in this audit, Partial rather than Not Implemented. Where CSF found Detect and Respond to be entirely absent, the CIS Controls most directly tied to those Functions (Control 8, Control 13, Control 17) all score Not Implemented here as well. Two independent scoring methods, applied to the same evidence base, reached the same conclusion.

---

## Top 5 Priority Controls

**1. Control 6, Access Control Management.** Closes GAP-017 (no MFA anywhere in the organization), the single most repeatedly cited authentication gap across all three projects, deployable at effectively $0 cost through MedDefense's existing O365 E3 licensing.

**2. Control 12, Network Infrastructure Management.** Closes GAP-014, independently confirmed as the single most-referenced weakness in this entire program, appearing in 6 of 8 distinct kill chains and scenarios, more than any other gap identified anywhere.

**3. Control 8, Audit Log Management.** Closes GAP-004, one of "The Critical Three" gaps identified in the 1x01 correlation work, and the direct, confirmed root cause behind the cryptominer compromise that ran undetected on billing-srv-01.

**4. Control 4, Secure Configuration of Enterprise Assets and Software.** Directly addresses the dominant vulnerability category in the entire 1x02 scan, misconfiguration, which accounted for 12 of 31 findings, more than any other category by a wide margin.

**5. Control 17, Incident Response Management.** Closes GAP-015, still unresolved as of the most recent budget review, and directly addresses a gap this program has already watched fail in practice once, the misdiagnosed billing-srv-01 incident.
