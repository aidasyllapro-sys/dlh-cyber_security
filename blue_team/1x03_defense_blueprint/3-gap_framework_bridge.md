# MedDefense Health Systems: The Gap-to-Framework Bridge

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** The re-prioritized gap list from 1x01 (Task 15), the vulnerability findings from 1x02, and the framework scores produced in Tasks 1 and 2 of this project **Purpose:** Connect every significant gap to a single, unbroken chain: the gap itself, the vulnerability evidence that proves it is real, the threat actor and attack path that would exploit it, the specific framework control that closes it, and the concrete action MedDefense should take. This chain is what turns a recommendation from "best practice" into an evidenced business case.

---

## Gap 1: GAP-014, Flat Network Architecture

```
Gap Reference: GAP-014
Description: No network segmentation exists anywhere in MedDefense's
  environment; any device can route to any other device on the full
  10.10.0.0/16 range.
Vulnerability Evidence: Findings 001, 003, 015, and 031 (1x02) all
  depend directly on this same absence of segmentation to reach beyond
  their initial point of compromise; this project's own Network Posture
  analysis (1x02, Task 14) confirmed the flat network as a risk
  multiplier across every finding it touches, not an isolated issue.
Threat Context: Ransomware Groups, the #1-ranked threat actor (1x01),
  via Kill Chain 1; independently confirmed as the single most-referenced
  gap across the entire program, appearing in 6 of 8 distinct kill
  chains and scenarios built in 1x01 (Task 15).
NIST CSF Function: Protect (PR.IR, Technology Infrastructure Resilience;
  PR.PS, Platform Security).
CIS Control: Control 12, Network Infrastructure Management (Safeguard
  12.2, establish and maintain a secure network architecture, IG2).
Recommended Action: Implement network segmentation separating server,
  workstation, medical device, and site-specific traffic into
  restricted, purpose-built VLANs, already the top-funded line item in
  this program's own remediation budget (1x02, Task 20).
```

---

## Gap 2: GAP-003, EHR Database Network-Wide Exposure

```
Gap Reference: GAP-003
Description: ehr-db-01's PostgreSQL configuration accepts connections
  from the entire internal network rather than restricting access to
  ehr-srv-01 specifically.
Vulnerability Evidence: Finding 003 (1x02), carrying no CVE or CVSS
  score at all, yet independently confirmed as the finding most likely
  to cause the greatest overall damage in the entire assessment (1x02,
  Task 18), given it is reachable by every threat actor type profiled
  in this program.
Threat Context: All six actor types from the 1x01 Threat Actor Matrix,
  via Kill Chains 1, 3, and 5; one of "The Critical Three" gaps
  identified in the 1x01 Gap-Threat Correlation (Task 15).
NIST CSF Function: Protect (PR.AA, Identity Management, Authentication,
  and Access Control; PR.PS, Platform Security).
CIS Control: Control 4, Secure Configuration of Enterprise Assets and
  Software (Safeguard 4.6, securely manage enterprise assets and
  software, IG1).
Recommended Action: Restrict pg_hba.conf to accept connections only
  from ehr-srv-01's specific address and add a host-based firewall rule
  enforcing the same restriction, already scheduled as an Immediate-tier
  action in this program's own remediation timeline (1x02, Task 20).
```

---

## Gap 3: GAP-004, No Centralized Detection Capability

```
Gap Reference: GAP-004
Description: No centralized logging, SIEM, or intrusion detection
  capability exists anywhere in MedDefense's environment.
Vulnerability Evidence: This project's own Lynis self-audit (1x02, Task
  8) directly confirmed "no IDS/IPS tooling" and no audit daemon on a
  comparable system; Finding 027 (1x02) separately confirms 15
  workstations show endpoint protection inactive with no alert generated
  to notice it.
Threat Context: All six actor types benefit from this gap equally, since
  it is the reason a real compromise (the billing-srv-01 cryptominer, GAP-005's own live example) already went undetected for an extended
  period; independently named one of "The Critical Three" gaps in the
  1x01 Gap-Threat Correlation.
NIST CSF Function: Detect (DE.CM, Continuous Monitoring; DE.AE, Adverse
  Event Analysis).
CIS Control: Control 8, Audit Log Management (Safeguard 8.2, collect
  audit logs, IG1), extending to Control 13, Network Monitoring and
  Defense (Safeguard 13.1, centralize security event alerting, IG2).
Recommended Action: Deploy centralized log collection and alerting for
  MedDefense's Critical Assets first (the EHR system, the domain
  controller, and the backup infrastructure), consistent with the Detect
  Function's modest, achievable 6-month target established in Task 1 of
  this project.
```

---

## Gap 4: GAP-017, No Multi-Factor Authentication

```
Gap Reference: GAP-017
Description: No multi-factor authentication is deployed anywhere in the
  organization, despite MedDefense's O365 E3 licensing already including
  the capability at no additional cost.
Vulnerability Evidence: Finding 009 (1x02), SSH password authentication
  still enabled on billing-srv-01, is the clearest technical manifestation
  of this broader organizational gap.
Threat Context: Ransomware Groups, via Kill Chain 1; this gap is also
  the specific reason a real-world identity-layer vulnerability class
  (illustrated by the Entra ID finding in 1x02's OSINT research, Task 9)
  cannot be assumed fully mitigated even where MFA exists, making its
  absence here particularly consequential.
NIST CSF Function: Protect (PR.AA, Identity Management, Authentication,
  and Access Control).
CIS Control: Control 6, Access Control Management (Safeguards 6.3, 6.4,
  and 6.5, requiring MFA for externally-exposed applications, remote
  access, and administrative access respectively, all IG1).
Recommended Action: Enable MFA enforcement organization-wide through
  MedDefense's existing O365 E3 licensing, a $0 incremental licensing
  cost already confirmed in Project 0x00.
```

---

## Gap 5: GAP-006, Backup Single Point of Failure

```
Gap Reference: GAP-006
Description: NAS-01, MedDefense's sole backup infrastructure, is
  co-located with the production systems it is meant to protect, with no
  offline or immutable copy.
Vulnerability Evidence: Finding 015 (1x02), and the CVE-2024-10441
  unauthenticated remote code execution vulnerability discovered through
  independent OSINT research (1x02, Task 9) on the exact software
  version this same device runs.
Threat Context: Ransomware Groups specifically, via Kill Chain 1, whose
  own documented affiliate playbook explicitly instructs operators to
  "identify and neutralize backups before deploying payload" (1x01, Task
  2), making this gap the doctrinal target of the organization's
  highest-priority threat actor.
NIST CSF Function: Recover (RC.RP, Incident Recovery Plan Execution).
CIS Control: Control 11, Data Recovery (Safeguard 11.4, establish and
  maintain an isolated instance of recovery data, IG1).
Recommended Action: Patch the confirmed CVE on NAS-01 and establish a
  genuinely isolated backup copy, both already scheduled within the
  Short-term tier of this program's remediation timeline (1x02, Task
  20).
```

---

## Gap 6: GAP-009, No Periodic Compliance and Hardening Review

```
Gap Reference: GAP-009
Description: No recurring process exists to review system configurations
  against a hardening baseline, allowing insecure default settings to
  persist indefinitely once deployed.
Vulnerability Evidence: Finding 007 (1x02), LDAP signing left at its
  insecure Windows default on the domain controller, is the clearest
  direct example; this project's own Vulnerability Profile analysis
  (1x02, Task 21) identified misconfiguration as the dominant category
  in the entire scan specifically because this review process has never
  existed.
Threat Context: Ransomware Groups and Organized Crime broadly, via
  credential relay and elevation of privilege techniques; this gap was
  independently upgraded from High to Critical in the 1x01 Gap-Threat
  Correlation given its role as the administrative root cause behind
  multiple separately-scored findings.
NIST CSF Function: Govern (GV.OV, Oversight).
CIS Control: Control 7, Continuous Vulnerability Management (Safeguard
  7.1, establish and maintain a vulnerability management process, IG1).
Recommended Action: Establish a recurring configuration and hardening
  review cycle, built directly on the rescan cadence already recommended
  in this program's own Validation Plan (1x02, Task 23).
```

---

## Gap 7: GAP-015, No Incident Response Plan

```
Gap Reference: GAP-015
Description: No documented, tested incident response plan exists
  anywhere in the organization.
Vulnerability Evidence: Not tied to a single scan finding, since this is
  a process gap rather than a technical one; its consequence is directly
  evidenced by the billing-srv-01 cryptominer incident, where the
  responding administrator misdiagnosed an active compromise as a
  hardware performance issue (0x00, Task 2).
Threat Context: Every threat actor type benefits equally from this gap,
  since it determines how much damage any successful compromise is
  allowed to accumulate before MedDefense notices and responds,
  independent of which actor or vector succeeded first.
NIST CSF Function: Respond (RS.MA, Incident Management).
CIS Control: Control 17, Incident Response Management (Safeguards 17.1
  and 17.2, designating incident-handling personnel and maintaining
  reporting contact information, both IG1).
Recommended Action: Draft and formally exercise an incident response
  plan, achievable within this program's own 6-month timeframe given it
  is primarily a documentation and process exercise rather than a
  costly technical buildout (Task 1 of this project).
```

---

## Gap 8: GAP-012, Incomplete Security Awareness Training

```
Gap Reference: GAP-012
Description: Security awareness training completion is inconsistent
  across MedDefense's sites, as low as 58% at one location.
Vulnerability Evidence: Not tied to a specific 1x02 scan finding, since
  training completion is not something a network scanner measures
  directly; its consequence is evidenced through 1x01's Human Vector
  analysis (Task 4), which modeled a plausible spear-phishing scenario
  against the IT Director using exactly this gap as its precondition.
Threat Context: Ransomware Groups, via Kill Chain 1, Step 2, the literal
  spear-phishing entry point of the organization's #1-ranked threat;
  this gap was independently upgraded from Medium to High severity in
  the 1x01 Gap-Threat Correlation (Task 15) once this connection was
  established.
NIST CSF Function: Protect (PR.AT, Awareness and Training).
CIS Control: Control 14, Security Awareness and Skills Training
  (Safeguard 14.2, train workforce to recognize social engineering
  attacks, IG1).
Recommended Action: Extend mandatory phishing-simulation and security
  awareness training to full organization-wide coverage, directly
  targeting the specific entry vector already confirmed in the
  organization's highest-priority kill chain.
```

---

## Traceability Summary Table

|Gap|Vulnerability Evidence|Threat Context|NIST CSF Function|CIS Control|
|---|---|---|---|---|
|GAP-014 (flat network)|Findings 001, 003, 015, 031|Ransomware Groups, Kill Chain 1 (6 of 8 paths overall)|Protect (PR.IR / PR.PS)|Control 12 (Network Infrastructure Management)|
|GAP-003 (EHR DB exposure)|Finding 003|All 6 actor types, Kill Chains 1, 3, 5|Protect (PR.AA / PR.PS)|Control 4 (Secure Configuration)|
|GAP-004 (no detection)|Lynis audit, Finding 027|All actor types; enabled the undetected cryptominer|Detect (DE.CM / DE.AE)|Control 8 / Control 13|
|GAP-017 (no MFA)|Finding 009|Ransomware Groups, Kill Chain 1|Protect (PR.AA)|Control 6 (Access Control Management)|
|GAP-006 (backup SPOF)|Finding 015, CVE-2024-10441|Ransomware Groups, Kill Chain 1 (doctrinal target)|Recover (RC.RP)|Control 11 (Data Recovery)|
|GAP-009 (no hardening review)|Finding 007|Ransomware/Organized Crime, credential relay|Govern (GV.OV)|Control 7 (Continuous Vulnerability Management)|
|GAP-015 (no IR plan)|Billing-srv-01 misdiagnosis (0x00)|All actor types (response failure amplifier)|Respond (RS.MA)|Control 17 (Incident Response Management)|
|GAP-012 (training gap)|1x01 Human Vector scenario|Ransomware Groups, Kill Chain 1 Step 2|Protect (PR.AT)|Control 14 (Security Awareness Training)|

This table is the single-view answer to the Board's question from this project's own introduction: every recommendation that follows in this strategy traces backward through this exact chain, from a specific framework control, through a named threat and a confirmed vulnerability, to the original gap, rather than resting on an unsupported claim of best practice.
