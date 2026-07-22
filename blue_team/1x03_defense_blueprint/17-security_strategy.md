# MedDefense Health Systems

## Security Strategy Document

**Prepared for:** The Board of Directors, MedDefense Health Systems **Prepared by:** Aïda Sylla, Security Analyst, Office of the Deputy CISO **Sponsor:** James Chen, Deputy CISO **Companion documents:** Security Posture Assessment (Project 0x00), Threat Landscape Report (Project 1x01), Vulnerability Assessment Summary (Project 1x02). Together, these four documents form the complete security intelligence and strategy package: what MedDefense has, who threatens it, where the cracks are, and now, what to do about it and how MedDefense knows it is worth the money. **Classification:** Internal, Board Distribution

---

## 1. Executive Summary

MedDefense enters this strategy with a security posture best described in its own numbers: zero of the 18 CIS Controls fully implemented, three of six NIST CSF Functions rated Not Implemented or Partial at best, and a combined annual expected loss across this program's top five quantified risks exceeding $7.4 million. This is not a dramatic claim; it is the arithmetic result of three prior projects' worth of evidence, converted here into dollars a CFO can evaluate directly.

**The strategic approach** adopts NIST CSF 2.0 as the organizing structure for Board communication and program governance, CIS Controls v8 Implementation Group 1 as the concrete, executable safeguard set a two-person security team can actually deliver, and defers formal ISO 27001 certification until a specific business driver justifies its cost. Every risk in this strategy traces to a named gap from the posture assessment, a named vulnerability finding from the technical assessment, and a named threat actor from the threat landscape report, not to a "best practice" assertion.

**Total investment requested: $95,800 this fiscal year**, against a fixed $120,000 annual security budget, delivering an estimated **$6,072,898 in combined annual risk reduction**, a return exceeding 60 times its cost. A further $24,200 is held in deliberate reserve rather than spent to the last dollar.

**Top 3 priority actions:** first, close the EHR database's network-wide exposure, a $500 configuration change returning over $3.2 million in net annual value, the single highest return on investment identified anywhere in this analysis. Second, complete network segmentation and MFA deployment together, the two controls that directly disrupt the organization's single highest-priority ransomware kill chain. Third, execute the five zero-cost quick wins identified in this strategy within the first two weeks, before the larger capital items even clear procurement, to demonstrate that this program executes, not just analyzes.

---

## 2. Governance Framework

**Framework selection (Task 0):** NIST CSF 2.0 answers "what should we do," providing the strategic vocabulary this document and every future Board conversation will use. CIS Controls v8, starting from Implementation Group 1, answers "how should we do it," providing the specific, testable safeguards MedDefense's small team can actually execute. Formal ISO 27001 certification, which answers "can we prove it," is deliberately not pursued this year: the cost of a dedicated management-system build-out and third-party audit is not justified until a specific contract, payer relationship, or insurance requirement demands it, though this program adopts ISO 27001's underlying documentation discipline informally.

**NIST CSF Current vs. Target Profile (Task 1):**

|Function|Current Level|6-Month Target|
|---|---|---|
|Govern|Partial|Managed|
|Identify|Managed|Optimized|
|Protect|Partial|Managed|
|Detect|Not Implemented|Partial|
|Respond|Not Implemented|Managed|
|Recover|Partial|Managed|

Identify is MedDefense's strongest Function today, built directly through this program's own asset registry, criticality assessment, and vulnerability work. Detect is deliberately given the most modest 6-month target of any Function: moving from zero monitoring capability to full maturity in six months is not realistic for a two-person team, and this strategy sets an honest, achievable goal rather than an aspirational one.

**CIS Controls maturity scorecard (Task 2):** 0 of 18 Controls fully Implemented, 6 rated Partial, 12 rated Not Implemented. This result independently confirms the NIST CSF findings above through a completely different scoring methodology, the strongest form of validation this program's own analysis can produce.

**Governance structure (Task 4):** The CEO holds sole Accountability for budget approval, policy approval, and risk acceptance decisions; James Chen is Responsible for preparing and recommending each; Sarah Park's IT team executes approved technical remediation; Department Heads hold real, substantive Responsible or Consulted roles specifically where clinical operations or their own data domain is affected, directly resolving the authority disputes that opened this governance work. Given the vacant CISO position and this program's $120,000 total budget constraint, a virtual/fractional CISO arrangement is recommended over a full-time hire as a near-term bridge, revisited as the program matures.

---

## 3. Quantitative Risk Analysis

**Top 5 risks by Annualized Loss Expectancy (Task 6):**

|Risk|ALE|
|---|---|
|EHR database breach|$4,083,750|
|Ransomware via VPN gateway|$2,864,400|
|Backup infrastructure compromise|$272,500|
|Ransomware via billing-srv-01|$137,170|
|Medical device patient safety incident|$70,000|

**Risk Register summary (Task 10):** 10 risks formally tracked, Inherent Risk Scores ranging from 8 to 20 on a 25-point scale, spanning Operational, Compliance, Financial, and Strategic categories. Every risk traces to a specific 0x00 gap, a specific 1x02 vulnerability finding, and a specific 1x01 threat actor, the full traceability chain this strategy's every recommendation depends on.

**Risk appetite (Task 16):** MedDefense accepts moderate operational and financial risk in service of patient care within realistic constraints, but treats any risk with a credible path to patient harm as an absolute limit that must always be mitigated or compensated. Acceptance of risks under $50,000 ALE sits within the Deputy CISO's discretion; risks between $50,000 and $500,000, or touching regulated patient data, require CEO approval; risks exceeding $500,000 or carrying any patient-safety dimension require formal, documented Board-level decision.

---

## 4. Control Strategy

**Cost-benefit results (Task 7):** Eight proposed controls evaluated with full SLE/ARO/ALE rigor: six Justified (Segmentation, MFA, SIEM, EDR, Westside Firewall, Offsite Backup), one Marginal (Full Medical Device Isolation, pending a dedicated MRI/Philips ALE study), and one Not Justified (24/7 outsourced SOC staffing, whose $120,000 cost alone would consume the entire annual security budget for negative net value once evaluated against the SIEM already funded).

**Budget allocation (Task 8):** $95,800 funded across six controls this fiscal year, delivering $6,168,698 in gross ALE reduction against a combined cost that returns the program's investment many times over. Full Medical Device Isolation ($18,000) is deferred, not for budget reasons alone but pending stronger evidence; 24/7 SOC staffing is rejected outright on the math. $24,200 remains in deliberate reserve.

**Control selection (Task 11):** Every risk in the register maps to at least one specific CIS Control safeguard and NIST CSF Category, with implementation dependencies mapped explicitly: Network Segmentation must precede both medical device VLAN isolation and full protection of the MRI risk; MFA must precede the vendor-access jump-host; the ransomware backup patch must precede establishing an isolated recovery copy.

**Quick wins (Task 13):** Five actions, each $0 cost using existing licensing, staff, and infrastructure, executable within 14 days: MFA enforcement, EHR database access restriction, infusion pump default credential rotation, USB mass storage restriction, and drafting an initial incident response plan. These exist specifically to demonstrate program momentum before the larger capital items clear procurement.

---

## 5. Architecture Recommendations

**Network segmentation design (Task 14):** Seven VLANs replace MedDefense's current flat network: Server, Clinical Workstation, Medical Device (correcting the MRI workstation's current, undocumented placement on the general workstation subnet), Management, Guest/IoT, Westside, and Corporate HQ, enforced by ten specific firewall rules including explicit denies blocking direct workstation-to-database access and all medical-device-to-internet traffic.

**Kill chain disruption analysis:** Walking the organization's #1 kill chain (ransomware) through this architecture step by step shows the chain is fully broken at its lateral-movement stage, converting a single compromised workstation into a contained incident rather than an organization-wide catastrophe. Across the top 5 kill chains from 1x01, an honest accounting: approximately 20% (1 of 5) fully disrupted, 60% (3 of 5) meaningfully degraded but not fully closed, since this initial design groups all servers into one zone rather than pursuing full server-to-server micro-segmentation, and 20% (the Business Email Compromise chain) entirely unaffected, since it has no network-layer dependency at all.

---

## 6. Policy Foundation

**Acceptable Use Policy summary (Task 12):** An 8-section, signature-ready policy covering acceptable and prohibited use, personal devices and removable media (directly closing the technical gap behind RISK-007), password and MFA requirements, data handling by classification tier, and monitoring and enforcement, including a deliberate emergency exception so clinical staff facing a genuine patient emergency are never forced to silently work around the policy.

**Policy roadmap, what comes next:**

|Policy|Target Month|Rationale|
|---|---|---|
|Incident Response Policy|Month 1|Formalizes the Quick Win 5 draft into an approved, exercised policy|
|Identity and Access Management Policy|Month 2|Formalizes MFA and account lifecycle requirements alongside the MFA rollout|
|Data Classification and Handling Policy|Month 2|Formalizes the tiers the AUP references at a level of detail the AUP itself deliberately keeps brief|
|Vendor and Third-Party Risk Management Policy|Month 3|Closes GAP-026, directly addressing RISK-009, alongside the vendor jump-host control|
|Business Continuity and Disaster Recovery Policy|Month 5|Formalizes backup testing and RTO/RPO requirements alongside backup validation work|
|Change Management Policy|Month 6|Closes GAP-025, the administrative root cause behind several misconfiguration findings in 1x02|

---

## 7. Residual Risk Assessment

**Red team findings (Task 15):** With every funded control in place, Kill Chain 2 (opportunistic escalation from billing-srv-01 to the domain controller) remains fully viable, since this program's own Server VLAN groups the domain controller with other servers rather than isolating it separately. A concrete alternative attack path was constructed exploiting the deferred medical device isolation control and the rejected 24/7 SOC decision together. Most significantly, this exercise surfaced a gap none of the eight evaluated controls ever addressed at all: GAP-018, the absence of automated account deprovisioning, which defeats MFA entirely and remains exactly as exploitable as before this program began. Overall residual risk is rated **High**, a genuine reduction from the program's starting point, not a claim that the remaining exposure is small.

**Accepted risks (Task 16):** Three risks carry a formal, CEO-approved Accept decision for their residual exposure after mitigation: the MRI workstation's permanent end-of-life condition (bounded by an 18-month equipment lease), the infusion pump fleet's vendor-dependent firmware limitation, and the EHR database's residual exposure after its primary control, each with a documented compensating measure and review trigger, not a silent gap.

**Year 2 priorities:** Automated, HR-triggered account deprovisioning (closing GAP-018) is recommended as the top priority for next year's budget, ahead of the deferred Full Medical Device Isolation control, specifically because this year's red team exercise is what surfaced it as a genuine, previously unranked blind spot rather than a deliberately deprioritized item.

---

## 8. Implementation Roadmap

**Phase 1, Months 1-2: Quick Wins and Procurement.** All five quick wins (Task 13) execute in the first two weeks at $0 cost. In parallel, procurement begins for the segmentation hardware, EDR licensing, and SIEM infrastructure. The Incident Response Policy formalizes. _Success metric: all 5 quick wins verified complete within 14 days; procurement orders placed for all Phase 2 capital items by end of Month 2._

**Phase 2, Months 3-4: Core Controls Deployment.** Network segmentation architecture builds out across all 7 zones; EDR deploys to all endpoints including servers; SIEM tuning completes with alerting live on Critical Assets; offsite backup replication establishes; the Westside firewall replacement completes. The Identity and Access Management, Data Classification, and Vendor Risk Management policies formalize. _Success metric: Kill Chain 1 re-tested and confirmed broken at its lateral-movement step; all Risk Register KRIs reporting for the first time; residual risk on RISK-001 through RISK-005 reassessed against Task 6's projected post-control ALE figures._

**Phase 3, Months 5-6: Validation and Optimization.** A follow-up vulnerability scan confirms the corrected severity distribution this program's technical assessment established. A second red team exercise, following the same methodology as Task 15, tests whether the Year 1 program closed what it claimed to close. The Business Continuity and Change Management policies formalize. Year 2 budget planning begins, led by the GAP-018 priority this program's own red team work identified. _Success metric: a documented, board-presented comparison of Month 1 versus Month 6 CIS Controls and NIST CSF scores; a formal Year 2 budget proposal submitted before the current fiscal year closes._

---

## 9. Next Steps

This strategy closes the planning phase of MedDefense's security program. Three projects of diagnosis, what MedDefense has, who threatens it, and where the technical gaps are, converged in this fourth project into a funded, framework-aligned, governance-backed strategy with a defined 6-month execution path.

**The path from strategy to implementation continues directly into Project 1x04: The Cryptographic Foundation.** This strategy's own Data Handling section (Section 6) and this program's own prior findings already point to exactly why: backup data on NAS-01 was confirmed stored unencrypted (1x02, Finding 015), DICOM medical imaging traffic was confirmed traversing the network in cleartext (1x02, Finding 024), and this strategy's own data classification tiers require encryption at rest and in transit as a stated policy requirement this program has not yet technically implemented. Where this project selected controls and built the architecture to contain and detect an attacker, Project 1x04 addresses the layer beneath: ensuring that even where an attacker reaches data, that data remains unreadable without the keys MedDefense controls, the next and necessary layer of defense this strategy's own architecture was built to support, not replace.
