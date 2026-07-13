# MedDefense Health Systems: Review of Marcus Webb's Draft Assessment

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** "MedDefense Security Assessment, DRAFT v0.3, Marcus Webb" (found in a sealed envelope, dated 3 months prior to this project), cross-referenced against the complete body of this project's own findings (Tasks 0–14) **Purpose:** Critically compare a predecessor's unfinished internal assessment with the assessment completed in this project, reconcile disagreements with evidence, incorporate valid findings that were missed, and use Marcus's final, unfinished section as the bridge to the next phase of work.

---

## Part 1: Comparative Analysis

### Comparison Table

| Finding                                                                         | Marcus's Assessment                                                                                                                                                      | Your Assessment                                                                                                                                                                               | Agree/Disagree                                                                                    | Resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Network segmentation (M-01)                                                     | Critical: entire network flat, no VLANs, any device can reach any other                                                                                                  | GAP-014: Critical, confirmed empirically by the Task 7 network scan ("a device on any subnet can reach any other device on any other subnet")                                                 | **Agree**                                                                                         | Independently confirmed through direct technical evidence (the scan) rather than observation alone, which Marcus did not have access to. Same conclusion, stronger evidentiary basis.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Backup isolation (M-02)                                                         | Critical: NAS co-located with production; recovery depends on a "monthly offsite tape rotation," up to 30 days of data loss                                              | GAP-006: Critical, co-located NAS confirmed; but Artifact 5 (Task 4) explicitly states **"OFFSITE/CLOUD BACKUP: None."** No tape rotation is documented anywhere in the current environment.  | **Partial Disagree: genuine, unresolved discrepancy**                                             | Marcus's draft references an offsite tape rotation that does not appear in the current backup documentation reviewed in this project. I cannot determine with confidence whether this rotation existed and was discontinued after Marcus's departure, or whether Marcus was working from an assumption rather than direct verification. **This should be verified directly with Sarah Park** if a tape rotation genuinely existed and was quietly discontinued, MedDefense's actual recovery posture has gotten worse since Marcus's draft, not stayed the same.                                                                                                                                                             |
| Medical IoT exposure (M-03)                                                     | High ("potentially CRITICAL given patient safety implications". Marcus hedged rather than committed)                                                                     | GAP-001: rated Critical outright (Task 8/12), independently validated by the real-world Gamma breach (Task 13)                                                                                | **Partial Agree: I would resolve in favor of Critical**                                           | Marcus's own language shows he was leaning toward Critical but stopped short, likely due to the document being an incomplete draft. My formal criteria (Critical asset + Restricted data + zero detective/corrective control, per the Task 12 prioritization rules) and the independent real-world validation in Task 13 both support committing to Critical rather than hedging.                                                                                                                                                                                                                                                                                                                                            |
| Absence of monitoring/detection (M-04)                                          | High                                                                                                                                                                     | GAP-004: Critical                                                                                                                                                                             | **Disagree on level, agree on substance**                                                         | GAP-004 affects every Critical-rated asset simultaneously and was the single factor present in **all 3 real-world breaches reviewed in Task 13. This meets the Critical threshold under the Task 12 rules, not just High. One notable detail: Marcus states the crypto-miner "ran for at least 2 weeks", a more specific timeframe than I was able to establish from the diagnostic excerpt alone in Task 2. This suggests Marcus had direct knowledge (e.g., ticket history) I did not have access to, and this specific figure should be treated as more reliable than my own more cautious "extended period" phrasing.                                                                                                    |
| No MFA (M-05)                                                                   | High                                                                                                                                                                     | GAP-017: Critical                                                                                                                                                                             | **Disagree on level, but Marcus's finding is more actionable than mine**                          | I would resolve this at Critical, validated directly by the Beta breach in Task 13 (MFA absence was the single control that would have stopped that real intrusion). More importantly: **Marcus's draft contains a cost detail my own Task 14 budget did not have**. He notes Microsoft Entra ID MFA is available at "$0 additional cost" for VPN and admin accounts through the existing O365 E3 license, with only EHR-level MFA requiring vendor engagement. My Task 14 estimate (~$8,000) assumed a new licensing cost; if Marcus's note is accurate, that budget line should be revised down substantially and the savings redirected to another gap. **This should be verified before finalizing next year's budget.** |
| Westside Clinic security (M-06)                                                 | High: Standalone finding covering the consumer router, no firewall, no managed switches, unlocked closet, and the VPN link's effect on Central's own risk                | Addressed only as scattered supporting details across GAP-014, Task 3, and the Asset Registry (A-017) — **never consolidated into its own Gap ID**                                            | **Marcus was right to call this out separately — I missed this as a standalone finding**          | Marcus's framing is genuinely better here: treating Westside as one consolidated site-level risk (rather than distributing it across several other findings) makes clearer that a compromise there has a direct path into Central via the VPN. **Added below as GAP-021.**                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Shared credentials in Radiology (M-07)                                          | Medium: Shared PACS login, no individual accountability, but limited to on-site access                                                                                   | Mentioned only as supporting evidence under GAP-009 and the Task 9 Data Map and **never given its own Gap ID**                                                                                | **Agree with Marcus's rating and reasoning**                                                      | Marcus's own operational context (he personally reported this to Sarah Park and received Radiology's pushback) is more grounded than my own treatment of it as a secondary detail. **Added below as GAP-022**, at Medium, consistent with his reasoning that on-site-only access meaningfully limits (without eliminating) the exposure.                                                                                                                                                                                                                                                                                                                                                                                     |
| Print server EOL (M-08)                                                         | Low: Low-value target, internal-only access                                                                                                                              | GAP-013: Low, same reasoning (EOL, low value, internal-only)                                                                                                                                  | **Agree**                                                                                         | Independent convergence on the same rating for the same reasons. This is one of the few findings where both assessments align completely without needing reconciliation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| TLS 1.0 enabled on web-srv-01 (Section 2, undocumented)                         | Identified but not written up. Flagged only as a to-do item                                                                                                              | Not identified anywhere in this project                                                                                                                                                       | **Valid finding I missed entirely**                                                               | No source available to me in this project included SSL/TLS configuration detail for web-srv-01. **Added below as GAP-023.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| No DLP controls (Section 2, undocumented)                                       | Identified but not written up                                                                                                                                            | GAP-019 (Task 13): Independently identified via the Beta breach validation                                                                                                                    | **Agree: Mutual, independent finding**                                                            | Both assessments arrived at the same conclusion through different paths (Marcus through direct observation, this project through real-world breach correlation), which reinforces confidence in the finding.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Unrestricted USB ports (Section 2, undocumented)                                | Identified but not written up. Flagged as a data exfiltration vector combined with no DLP                                                                                | Not identified anywhere in this project                                                                                                                                                       | **Valid finding I missed entirely**                                                               | **Added below as GAP-024.**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| No formal change management process (Section 2, undocumented)                   | Identified but not written up. Marcus explicitly connects this to the untested cron job that caused the 3-week-old backup at the time of the January ransomware incident | Not identified as its own gap. I documented the _symptom_ (the 3-week-old backup, referenced in Incident A and GAP-006) extensively but never identified the _process failure_ that caused it | **Valid finding I missed and it is a genuine root cause I should have caught**                    | This is the most significant miss in this entire review. I treated the stale backup as evidence supporting GAP-006 (backup resilience) without ever asking why the backup was stale in the first place. Marcus's note directly answers that question. **Added below as GAP-025.**                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| HQ building-managed network, no MedDefense visibility (Section 2, undocumented) | Identified but not written up                                                                                                                                            | Touched on tangentially in GAP-011 (unaudited HQ VPN ACLs) and the environment summary, but never framed as broadly as Marcus's note                                                          | **Partial agree. Marcus's framing is more complete**                                              | I focused narrowly on the VPN ACLs; Marcus's note correctly frames the larger issue — MedDefense has no visibility into the landlord's network security at all, of which the VPN is only one part. This is treated as a refinement of GAP-011 rather than a new gap, since the underlying asset and data are the same.                                                                                                                                                                                                                                                                                                                                                                                                       |
| MRI running Windows XP                                                          | Flagged only informally, in his own IT asset list note ("CRITICAL runs Windows XP. See separate file") **not present in this draft document's formal findings**          | GAP-002, with a full dedicated compensating-control strategy (Task 6)                                                                                                                         | **I have more complete documentation; Marcus clearly knew about it but never formalized it here** | See the Blind Spot Hypothesis section below. This appears to be an incompleteness issue, not a genuine miss on Marcus's part.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Server room / network closet physical access                                    | Reported verbally to James and Sarah "at least twice," per James's own account (Task 3) **not present in this draft document**                                           | GAP-007, fully documented with a formal physical walk-through (Task 3)                                                                                                                        | **I have more complete documentation; Marcus reported it through a different channel**            | See the Blind Spot Hypothesis section below.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Valid Marcus Findings: Newly added to the Gap Analysis

```
Gap ID: GAP-021
Title: Westside Clinic's consumer-grade network equipment and VPN
  configuration create a site-level risk that directly extends into
  Central's environment
Affected Asset(s): Netgear Nighthawk router (Task 7, A-017), ws-srv-01,
  Westside workstations (~45), Westside server closet
Data at Risk: All data traversing the Westside-to-Central VPN link —
  effectively any Restricted data Westside staff access at Central
Current Control Status: No dedicated firewall exists at Westside (the
  consumer router is the entire network boundary); the firewall rule
  governing this VPN link ("Allow-VPN-Westside," Task 4, Artifact 1) permits
  ALL services from Westside's subnet into Central's server subnet —
  a detail Marcus himself flagged as "too permissive" in his own notes.
What is Missing: Technical Preventive (a managed firewall/UTM device at
  Westside) and Technical Preventive (restrictive, service-specific VPN
  firewall rules, rather than the current ALL-services permission)
Risk Level: Critical
Risk Justification: This finding directly affects Central's server subnet
  (housing every Critical-rated asset in Task 8) via an ingress path with
  no detective or corrective control and an over-permissive firewall rule,
  meeting the Critical rule through its direct connection to Central's core
  infrastructure — not merely a Westside-local concern.
Potential Impact: A compromise of the Netgear router (a consumer device
  with no enterprise security features) would grant an attacker a direct,
  unrestricted path into Central's server subnet — a smaller-scale but
  structurally identical version of the lateral-movement risk described in
  GAP-014.
```

```
Gap ID: GAP-022
Title: Shared login credentials on the PACS workstation eliminate
  individual accountability for imaging data access
Affected Asset(s): pacs-srv-01 and its associated Radiology workstations
Data at Risk: Medical Imaging Data — Restricted (Task 9)
Current Control Status: A shared account ("raduser") is used by multiple
  Radiology staff; this was reported to IT and rejected by the department
  on operational-speed grounds, with no resolution reached.
What is Missing: Technical Preventive (an individual or fast-authentication
  mechanism, e.g., badge/proximity-card login — that does not sacrifice
  the department's legitimate speed requirement)
Risk Level: Medium
Risk Justification: Following Marcus's own operational assessment, PACS
  access is limited to on-site use, which meaningfully reduces (without
  eliminating) the exposure compared to a remotely accessible shared
  credential — this is a partial mitigating factor consistent with the
  Task 12 Medium-level rule.
Potential Impact: In the event of any inappropriate access to imaging data,
  MedDefense would have no way to determine which specific individual was
  responsible, undermining both accountability and any future incident
  investigation involving this system.
```

```
Gap ID: GAP-023
Title: web-srv-01 (patient portal) has TLS 1.0 enabled alongside TLS 1.2
Affected Asset(s): web-srv-01 (Task 7, A-011)
Data at Risk: Patient Medical Records accessed via the patient portal —
  Restricted (Task 9)
Current Control Status: No source in this project other than Marcus's
  draft addresses web-srv-01's TLS configuration; this was never verified
  independently in this assessment.
What is Missing: Technical Preventive (disabling TLS 1.0, retaining only
  TLS 1.2 or higher)
Risk Level: High
Risk Justification: TLS 1.0 is a deprecated, known-weak protocol; its
  presence on an internet-facing server hosting access to Restricted data
  is a real exposure, though it is rated High rather than Critical because
  a properly configured client would still negotiate the stronger TLS 1.2
  by default. The risk is concentrated in forced-downgrade or legacy-client
  scenarios rather than being universally exploitable.
Potential Impact: An attacker capable of forcing a protocol downgrade could
  intercept or manipulate traffic to the patient portal using known TLS 1.0
  weaknesses.
```

```
Gap ID: GAP-024
Title: USB and removable media storage is unrestricted on all workstations,
  with no corresponding DLP control
Affected Asset(s): All Clinical and Administrative Endpoints (Task 8, both
  rated High), effectively all ~500+ workstations/laptops in the registry
Data at Risk: Patient Medical Records, Financial/Billing Data, Employee HR
  Records — Restricted and Confidential categories (Task 9)
Current Control Status: No Group Policy or equivalent control restricts
  USB storage device use anywhere in the environment.
What is Missing: Technical Preventive (GPO-enforced USB storage
  restriction) and this compounds directly with GAP-019 (no DLP), since
  neither control exists to catch what the other misses.
Risk Level: High
Risk Justification: Affects High-rated asset categories with a completely
  open, essentially undetectable data-exfiltration path, meeting the High
  rule; not rated Critical because exploitation requires physical device
  access, which is a meaningfully narrower condition than the network-wide
  exposures rated Critical elsewhere in this analysis.
Potential Impact: Any individual with legitimate or illegitimate access to
  a workstation can copy Restricted or Confidential data to a personal
  storage device with no technical control and no detection — a plausible
  vector for both insider misuse and opportunistic theft.
```

```
Gap ID: GAP-025
Title: No formal change management process exists for servers or network
  devices. Configuration changes are made ad hoc, without testing or
  approval
Affected Asset(s): Organization-wide — every server and network device in
  the Asset Registry
Data at Risk: Indirectly, all data categories (this gap is a root cause
  behind other) already-documented incidents rather than a direct exposure
  of one data category
Current Control Status: No documented change management process exists
  anywhere in this project's source material.
What is Missing: Administrative Preventive (a formal change request,
  testing, and approval process) and Administrative Detective (a change log
  or audit trail of what was modified, when, and by whom)
Risk Level: Critical
Risk Justification: This gap has already caused a documented, Critical-
  impact incident: the misconfigured cron job that left the backup 3 weeks
  out of date at the time of the January ransomware event (Incident A,
  Task 1) was, per Marcus's own note, an untested change. A root cause with
  a demonstrated Critical-severity consequence and no preventive or
  detective control meets the Critical rule directly.
Potential Impact: Any future untested change (to a firewall rule, a backup
  job, an access control list, or a server configuration) carries the same
  risk of silently degrading a critical control, exactly as it already has
  once, without anyone noticing until the moment that control is needed and
  fails.
```

### Findings this assessment identified that Marcus's draft missed

2 significant findings from this project are absent from Marcus's document entirely, despite evidence he was aware of at least one of them:

1. **The MRI's Windows XP situation (GAP-002, Task 6).** Marcus's own IT asset list (Task 0) contains his own handwritten flag: "CRITICAL - runs Windows XP. See separate file." He clearly knew about this and considered it critical. He simply never got to write it into this particular draft document, and the "separate file" he references was apparently never found (possibly among the files he mentions never transferring from his laptop before leaving). **Hypothesis: time pressure and document incompleteness**, not a genuine gap in his knowledge.
2. **Server room and network closet physical access (GAP-007, Task 3).** Per James's own account at the start of this project, Marcus raised this issue verbally "at least twice." It never made it into this written draft. **Hypothesis: Marcus may have considered this "already reported" through a different channel** (direct conversations with James and Sarah) and did not feel it needed to be duplicated in a technical draft document. Or, again, simply ran out of time given the document's explicit "DRAFT v0.3, INCOMPLETE" status.

Beyond these 2, several findings from later stages of this project (the shadow IT systems in Task 11, the account-deprovisioning and DMZ-verification gaps from Task 13, and the full Control Matrix effectiveness ratings in Task 10) are absent from Marcus's draft. **This is best explained by scope and access, not oversight**: the network scan (Task 7) was commissioned by James specifically for this project, after Marcus's departure; the shadow IT conversation with Mike Torres happened independently of Marcus's tenure; and the real-world breach correlation (Task 13) and structured control-effectiveness rating (Task 10) are later-stage analytical work that goes beyond what an initial posture-assessment draft would typically contain. Marcus's document reads as Phase 1 of the same process this project completed through Phase 4.

---

## Part 2: The last page

Marcus's final, unfinished section (mapping MedDefense's exposure against the external threat landscape) is the natural continuation of everything documented in this project, not a separate task. This internal posture assessment has already shown, independently and repeatedly, the exact combination Marcus flagged as most dangerous even before finishing his own threat-actor research: a flat network (GAP-014), no MFA (GAP-017), and no monitoring (GAP-004) and the Task 13 validation against real breach data confirms this is precisely the combination ransomware-as-a-service operators have already used to take down comparable hospitals, not a hypothetical concern. Understanding _what_ is broken internally was always going to be necessary but insufficient on its own; knowing _who_ is likely to exploit it, and _how_ (via MITRE ATT&CK techniques like T1190, T1566, and T1078, as Marcus began mapping), is what turns this assessment from a list of weaknesses into a prioritized defense against the specific threats MedDefense actually faces. Marcus's unfinished files, the CISA and HC3 threat briefs he never transferred off his laptop, should be the starting point for that next phase, not a rebuild from scratch.
