# MedDefense Health Systems: The NIST CSF Mapping

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** `nist-csf-reference.txt`, cross-referenced against every deliverable of Project 0x00 (Security Posture Assessment), Project 1x01 (Threat Landscape Report), and Project 1x02 (Vulnerability Assessment) **Purpose:** Build MedDefense's Current Profile against all six CSF 2.0 Functions. This profile, not an abstract compliance checklist, is the foundation the entire 6-month strategy is built on: the gap between where MedDefense stands today and where it needs to be in 6 months is what drives every prioritization decision in this project.

---

## Function 1: GOVERN (GV)

```
Function: GOVERN
Current Level: Partial

Evidence: Before this engagement began, MedDefense had no dedicated
  security function at all (0x00, Task 0). When directly asked by
  auditors which security framework MedDefense follows, Sarah Park's own
  answer was "none formally," the exact admission that opened this
  project. No documented cybersecurity policy, no formally assigned
  security roles beyond the Deputy CISO position itself, and no
  supply-chain risk management process existed prior to this program
  (1x01's own Supply Chain Question, Task 5, was a one-time assessment,
  not an ongoing GV.SC process). The first genuine risk-management
  decisions MedDefense has ever formally documented are the risk
  treatment decisions produced in 0x00 (Task 14), meaning some Govern-
  adjacent activity now exists, but only as a byproduct of this
  engagement, not as an organizational capability that predates it.

Key Gaps: No documented cybersecurity policy and no formal risk
  management strategy exist independent of this project's own output.
  GAP-009 (no periodic compliance or hardening review, established in
  0x00 and cited repeatedly throughout 1x01 and 1x02 as a root cause
  behind other findings) is the clearest single piece of evidence that
  governance, not just technical control, is where MedDefense's weakest
  foundation sits.

Target Level: Managed within 6 months. This is achievable specifically
  because the hardest part, the actual risk analysis and prioritization
  work, is already complete through this program's own prior three
  projects; what remains is formalizing it into a documented policy
  (a deliverable already scoped later in this same project) and
  assigning clear, written ownership for ongoing review, not building
  net-new analytical capability from scratch.
```

---

## Function 2: IDENTIFY (ID)

```
Function: IDENTIFY
Current Level: Managed

Evidence: MedDefense had no reliable asset inventory before this
  engagement; the 0x00 Asset Registry (Task 7) was the first one ever
  built, and the reconciliation process against the network scan
  directly surfaced multiple undocumented shadow IT devices (an
  unidentified Linux host on the server subnet and a second unidentified
  device at Westside) that no prior inventory had ever captured. Since
  then, MedDefense has produced a full Criticality Assessment (0x00),
  a complete Threat Actor Matrix and kill chain analysis (1x01), and a
  31-finding Vulnerability Assessment supplemented by independent OSINT
  research (1x02). The substance of Identify is now genuinely
  comprehensive, arguably the strongest of the six Functions in this
  assessment.

Key Gaps: What exists today is a single, thorough, point-in-time
  assessment, not yet a proven repeatable process. 1x02's own Validation
  Plan (Task 23) recommended a weekly-critical, monthly-full rescan
  cadence and a quarterly OSINT research cycle, but neither has actually
  run on a recurring basis yet; the entire body of Identify evidence
  MedDefense has today reflects one assessment cycle, not an
  institutionalized capability proven to repeat.

Target Level: Optimized within 6 months. This Function is the closest to
  full maturity of any assessed here, and the remaining gap is
  operational discipline (actually executing the recommended cadence
  more than once) rather than new analytical capability, making
  Optimized a realistic 6-month target where it would not be for a
  Function starting from a weaker baseline.
```

---

## Function 3: PROTECT (PR)

```
Function: PROTECT
Current Level: Partial

Evidence: The 1x02 vulnerability scan is the direct evidence base here,
  and it describes an environment with real but deeply inconsistent
  protective coverage. Some baseline controls do exist: a host-based
  firewall is active (confirmed directly via the Lynis self-audit in
  1x02, Task 8), and Sophos endpoint protection is deployed
  organization-wide, though 15 workstations show it inactive or not
  reporting (Finding 027). Against that, foundational protections are
  simply absent at the organizational level: no multi-factor
  authentication exists anywhere in the environment (GAP-017), no
  server-class endpoint protection exists (GAP-005, the confirmed root
  cause behind an undetected cryptominer compromise), the internal
  network has no segmentation at all (GAP-014, independently identified
  as the single most-referenced weakness across all three projects), and
  100% of scanned medical devices still carry unchanged default
  credentials. Three end-of-life systems (a Windows XP MRI workstation,
  a Windows Server 2012 R2 print server, and an unsupported Ubuntu 18.04
  billing server) remain in active clinical and financial use.

Key Gaps: The absence of network segmentation (GAP-014) and the absence
  of MFA (GAP-017) are the two most consequential gaps in this Function,
  and not coincidentally the two gaps this program's own cross-project
  correlation work (1x01, Task 15) already identified as carrying the
  highest leverage of any single fix available to MedDefense.

Target Level: Managed within 6 months. This target is realistic, not
  aspirational, specifically because the two highest-leverage fixes
  carry unusually low cost for their impact: MFA is deployable at
  effectively $0 through MedDefense's existing O365 E3 licensing
  (already confirmed in 0x00), and network segmentation is the
  top-funded line item in this program's own remediation budget.
```

---

## Function 4: DETECT (DE)

```
Function: DETECT
Current Level: Not Implemented

Evidence: This is the most unambiguous rating in this entire assessment,
  confirmed independently by three separate sources rather than a single
  observation. Marcus's own predecessor notes explicitly described zero
  monitoring capability before this engagement began. The 1x02 Lynis
  self-audit independently confirmed the same gap on a comparable
  system: "Checking for IDS/IPS tooling: NONE," no audit daemon, no
  process accounting. Most directly, this gap is not theoretical:
  MedDefense's own incident history includes a cryptominer that ran
  undetected on billing-srv-01 for an extended period specifically
  because no detection capability existed to notice it (0x00, Task 2).
  A gap this well-corroborated, with a real, already-realized
  consequence attached to it, does not qualify as merely Partial.

Key Gaps: No centralized logging, no SIEM or log correlation capability,
  no IDS/IPS anywhere in the environment, and no audit trail sufficient
  to reconstruct what happened during a security event after the fact.
  GAP-004 is not simply one gap among many; it was independently
  identified as one of "The Critical Three" in the 1x01 Gap-Threat
  Correlation (Task 15), appearing across the widest spread of distinct
  attack paths of any single gap in the entire program.

Target Level: Partial within 6 months, stated as a deliberately modest
  and honest target rather than an aspirational one. Moving from zero
  detection capability to a mature, continuously monitored, correlated
  detection program is not realistic for a two-person security team in
  six months regardless of budget; establishing basic centralized
  logging and alerting on the organization's Critical Assets specifically
  (the EHR system, the domain controller, and the backup infrastructure)
  is the achievable, meaningful step this timeframe actually supports.
```

---

## Function 5: RESPOND (RS)

```
Function: RESPOND
Current Level: Not Implemented

Evidence: GAP-015 (no incident response plan) was identified as a
  Critical gap in 0x00's own posture assessment and remains unresolved,
  still carried as reserved, uncommitted budget as of the most recent
  risk treatment review. MedDefense's only real evidence of an incident
  response in practice, the handling of the billing-srv-01 cryptominer,
  is evidence against maturity rather than for it: the responsible
  administrator's own diagnosis attributed the compromise to a hardware
  performance issue, a conclusion this program's own root-cause analysis
  directly refuted (0x00, Task 2). No breach notification procedure or
  defined communication plan exists anywhere in this program's
  documentation, a genuine regulatory exposure given the volume of
  patient health information this organization holds.

Key Gaps: No documented, tested incident response plan exists at all,
  and the one real-world incident on record was misdiagnosed by the
  person responding to it, direct evidence that the absence of a formal
  plan has already produced a real, not hypothetical, response failure.

Target Level: Managed within 6 months. Unlike Detect, this target is
  achievable specifically because building an incident response plan is
  primarily a documentation and process exercise, not a costly technical
  buildout requiring new tooling or headcount; a two-person team can
  realistically draft, review, and begin exercising a formal IR plan
  within this timeframe if it is prioritized, which this project's own
  roadmap does.
```

---

## Function 6: RECOVER (RC)

```
Function: RECOVER
Current Level: Partial

Evidence: Backup infrastructure does exist and is operational, placing
  this Function above Detect and Respond in current maturity, but it
  rests on a fundamentally compromised architecture. GAP-006 (backup
  single point of failure, NAS-01 co-located with the production systems
  it protects) was identified in 0x00 and remains open. 1x02's own OSINT
  research (Task 9) subsequently discovered an unauthenticated remote
  code execution vulnerability affecting the exact DSM software version
  running on this same NAS, meaning MedDefense's sole recovery mechanism
  is not merely architecturally fragile, it is now a confirmed, directly
  targetable Critical vulnerability in its own right. No evidence exists
  anywhere in this program's work of backups being tested for actual
  restorability, and no Recovery Time Objective or Recovery Point
  Objective has been formally defined for any system.

Key Gaps: The combination of architectural single-point-of-failure
  design and a confirmed, unpatched Critical vulnerability on the same
  device means MedDefense's recovery capability is currently both
  fragile and actively at risk simultaneously, not two separate,
  lower-severity concerns.

Target Level: Managed within 6 months. The most urgent component of this
  target, patching the newly-discovered NAS vulnerability and
  restricting its network exposure, is already scheduled within days in
  this program's own remediation timeline (1x02, Task 20); the remaining
  work, establishing a tested restore-verification process and formally
  defined RTOs, is a realistic addition to that same 6-month window.
```

---

## Summary: The Current Profile at a Glance

|Function|Current Level|Target Level (6 months)|
|---|---|---|
|Govern|Partial|Managed|
|Identify|Managed|Optimized|
|Protect|Partial|Managed|
|Detect|Not Implemented|Partial|
|Respond|Not Implemented|Managed|
|Recover|Partial|Managed|

The pattern across this profile is not random, and it echoes the same finding this program has reached independently several times before: MedDefense's _analytical_ capability (Identify) is now genuinely strong, built directly through this engagement's own work, while its _operational_ capability, especially the ability to notice an active compromise (Detect) and formally respond to one (Respond), remains the weakest link in the entire chain. This is the gap the remainder of this project's strategy is built to close.
