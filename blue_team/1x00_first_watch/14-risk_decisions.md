# MedDefense Health Systems: Risk Treatment Decisions

**Prepared by:** Security Analyst (Junior) **Prepared for:** James Chen, Deputy CISO **Source material:** Prioritized Gap Analysis (Task 12) and its Task 13 updates (GAP-014 through GAP-020) **Budget constraint:** $120,000 for the current fiscal year **Purpose:** Apply a formal risk treatment strategy to MedDefense's 7 highest-priority gaps and produce a budget that fits, or explicitly justifies exceeding, the available funding.

**Selection logic for the 7 gaps below:** MedDefense currently has 13 gaps rated Critical across Tasks 12–13. A $120,000 budget cannot mitigate all of them properly in one fiscal year — attempting to would mean under-funding everything and fixing nothing well. The 7 gaps selected here were chosen using two criteria: (1) they were independently validated as the highest-leverage, most cross-cutting weaknesses by the real-world breach analysis in Task 13 (detection, segmentation, backup resilience, and identity hygiene were the recurring themes across all three real breaches), and (2) each offers a genuinely achievable mitigation within this year's budget, rather than requiring the full $120,000 on its own. Gaps not selected this cycle are listed at the end with a brief rationale. They are not being ignored, only sequenced into a later phase.

---

## Treatment Decision 1

yaml

```yaml
Gap ID: GAP-004
Gap Title: No centralized log correlation or alerting exists anywhere in the organization
Risk Level: Critical (unchanged since Task 12; independently confirmed as the single
  factor common to all three real-world breaches reviewed in Task 13)

Treatment Strategy: Mitigate

Justification: James's own framing of the budget problem is the justification here —
  an $80,000 enterprise SIEM license alone would consume two-thirds of the entire
  annual budget for one control. Marcus had already begun researching Wazuh, an
  open-source SIEM/log-correlation platform, before he left (Task 4, Artifact 8). Given
  this gap is the one factor present in every real-world breach reviewed, it must be
  mitigated this year, but it must be mitigated affordably.

If Mitigate:
  - Proposed Control(s): Technical Detective — deploy Wazuh (or a comparable
    open-source log aggregation/alerting platform) to centralize logs from the
    FortiGate, Windows/Linux servers, and the EHR audit export, with baseline
    alerting rules for known-bad patterns (e.g., unusual outbound connections,
    off-hours privileged logins).
  - Estimated Cost: $10K–50K (targeting ~$20,000: server infrastructure, initial
    configuration, and implementation labor/consulting — deliberately a fraction of
    the $80,000 commercial-SIEM alternative)
  - Implementation Effort: Long-term (>1 month) — proper deployment, log-source
    integration, and rule-tuning cannot be rushed without generating excessive false
    positives/negatives.
  - Expected Risk Reduction: High. This does not eliminate the risk of compromise,
    but it directly closes the detection gap that allowed the billing-srv-01
    cryptominer to run undetected for an extended period, and addresses the exact
    weakness cited in Alpha's invisible 3-hour reconnaissance, Beta's unreviewed
    logs, and Gamma's 23-day dwell time.

Trade-offs: Open-source software has no vendor support contract or SLA. MedDefense's
  own IT staff (already stretched across a 12-person department covering three sites)
  must build and maintain the expertise to tune it correctly. A SIEM that generates
  alerts nobody reviews provides no more protection than the log files MedDefense
  already has (this is literally Beta's lesson #4: "logs without review are security
  theater"). This control's value depends entirely on a follow-on commitment to
  actually staff alert review, which is not itself funded by this line item.
```

---

## Treatment Decision 2

yaml

```yaml
Gap ID: GAP-014
Gap Title: The entire internal network is flat with no segmentation, enabling
  unrestricted lateral movement to any system
Risk Level: Critical (unchanged; confirmed as the architectural condition that let
  Alpha's attacker reach the domain controller in 3 hours)

Treatment Strategy: Mitigate

Justification: This is the root architectural cause behind several other gaps in this
  project (GAP-001's medical IoT exposure, GAP-003's database exposure), so mitigating
  it produces compounding risk reduction across multiple findings rather than a single
  one — the most efficient use of a constrained budget. A full, all-at-once
  segmentation of every device at every site is not feasible this year; this is
  proposed as Phase 1 of a multi-year project.

If Mitigate:
  - Proposed Control(s): Technical Preventive — VLAN-based segmentation at Central,
    Phase 1 scope: separate the server subnet, general workstation subnet, and a new
    dedicated medical-IoT VLAN (prioritized given the confirmed, vendor-disclosed CVE
    on the BD Alaris pumps), with firewall ACLs restricting traffic between segments
    to only what is operationally required.
  - Estimated Cost: $10K–50K (targeting ~$35,000: switch reconfiguration, firewall
    rule development, and phased-rollout project labor)
  - Implementation Effort: Long-term (>1 month) — must be carefully phased to avoid
    clinical disruption; an EHR- or imaging-affecting outage during migration would
    repeat the exact harm this project is trying to prevent.
  - Expected Risk Reduction: Very high. This directly shrinks the blast radius of any
    future compromise. A repeat of the billing-srv-01 cryptominer incident, or any
    new compromise, would no longer have unrestricted reach to the domain controllers,
    EHR database, or medical devices.

Trade-offs: Phase 1 will not cover Westside (still dependent on its consumer-grade
  router) or Corporate HQ, and will not achieve full micro-segmentation of every
  individual medical device, only a coarse-grained IoT VLAN this year. There is
  genuine operational risk during the cutover itself if not carefully planned and
  tested, and IT staff time devoted to this project is time not spent on other
  priorities.
```

---

## Treatment Decision 3

yaml

```yaml
Gap ID: GAP-006
Gap Title: The organization's only backup infrastructure is a single point of failure
  with no offsite or immutable copy
Risk Level: Critical (unchanged; Alpha's identical scenario — production and backup
  destroyed together — produced an 11-day outage and $5M in combined costs)

Treatment Strategy: Mitigate

Justification: This gap already has a ready-made, low-cost solution sitting on the
  shelf — Marcus obtained a vendor quote for AWS S3 offsite backup replication
  ($14,400/year, Task 4, Artifact 5) before his departure, and it was denied purely on
  budget grounds at the time. Given the severity this gap demonstrated in Alpha's real
  breach, and the low relative cost, this is one of the clearest "should already have
  been done" decisions in this entire portfolio.

If Mitigate:
  - Proposed Control(s): Technical Corrective — enable cloud/offsite replication of the
    existing Veeam backup job to AWS S3, ensuring at least one backup copy is not
    reachable from the same network as production systems.
  - Estimated Cost: $10K–50K (the vendor-quoted $14,400/year, at the low end of this
    bucket)
  - Implementation Effort: Short-term (<1 month) — Veeam already supports this
    integration; this is primarily a configuration and subscription activation, not a
    build project.
  - Expected Risk Reduction: High for the specific failure mode this addresses (total
    loss of both production and backup in a single event). It does not fix this gap's
    other limitations, 14-day retention, no full DR test ever performed, and several
    systems still excluded from backup entirely (pacs-srv-01, ad-dc-02, print-srv-01,
    Westside, medical device configs, O365). Those remain open items.

Trade-offs: This is a partial fix to a broader backup problem, not a complete one. It
  should not be presented to the Board as "backup is now solved." A full disaster
  recovery test (which failed to happen even once in the current environment) should
  still be scheduled using existing staff time, since an untested backup is not a
  verified backup, regardless of where it's stored.
```

---

## Treatment Decision 4

yaml

```yaml
Gap ID: GAP-001
Gap Title: Medical IoT (Infusion Pumps) has zero security control coverage of any kind
Risk Level: Critical (unchanged; Gamma's breach is close to a direct real-world replay
  of this exact exposure: default credentials, no segmentation, patient dosage data
  accessed)

Treatment Strategy: Mitigate

Justification: The full fix for this gap is the medical-IoT VLAN already scoped inside
  GAP-014's Phase 1 segmentation project — funding it twice would be wasteful. What
  this gap needs as its own, additional line item is a near-zero-cost, immediate action
  that does not need to wait for the segmentation project to finish: verifying and
  changing any default credentials on medical device management interfaces, exactly
  the specific detail that let Gamma's attackers reach dosage data even after they were
  already on the internal network.

If Mitigate:
  - Proposed Control(s): Technical Preventive — a one-time credential audit of all
    Philips IntelliVue and BD Alaris management interfaces, changing any default or
    vendor-standard credentials found (coordinated with Biomedical Engineering, per the
    explicit lesson from Gamma's report that this requires IT/security/biomed
    collaboration).
  - Estimated Cost: $0–1K (this is a labor-only action using existing staff time — no
    new technology purchase)
  - Implementation Effort: Quick Win (<1 week)
  - Expected Risk Reduction: Meaningful and immediate, at essentially no cost — even
    before the segmentation project (GAP-014) completes, this closes the single easiest
    exploitation step Gamma's attackers used once they reached the device network.

Trade-offs: This alone does not fix the underlying lack of segmentation. The devices
  remain reachable from the flat network until GAP-014's IoT VLAN phase is complete.
  This is a genuine quick win, not a substitute for the larger project.
```

---

## Treatment Decision 5

yaml

```yaml
Gap ID: GAP-017
Gap Title: Multi-factor authentication is not required for any remote access or
  clinical system, organization-wide
Risk Level: Critical (unchanged; this is the single control that would have most
  directly stopped Beta's real-world breach)

Treatment Strategy: Mitigate

Justification: This is one of the highest risk-reduction-per-dollar controls
  available to MedDefense. A full, immediate, organization-wide rollout to all ~2,000
  staff is not realistic within this budget cycle, but a phased rollout targeting the
  highest-risk accounts first (VPN access and privileged/EHR-administrative accounts)
  delivers most of the risk reduction at a fraction of the cost and disruption.

If Mitigate:
  - Proposed Control(s): Technical Preventive — enforce MFA on VPN access (Westside
    and HQ site-to-site paths, plus any individual remote-access accounts) and on
    privileged/administrative EHR accounts as Phase 1.
  - Estimated Cost: $1K–10K (targeting ~$8,000 for an initial phase covering
    remote-access and privileged accounts; a full org-wide rollout is a larger,
    separate next-fiscal-year cost)
  - Implementation Effort: Short-term (<1 month) for the Phase 1 scope.
  - Expected Risk Reduction: Very high for the specific accounts covered — a stolen,
    reused, or retained credential (like Beta's former employee's) would no longer be
    sufficient on its own for remote access into the highest-value systems.

Trade-offs: Staff outside this initial phase (the majority of the 2,000-person
  workforce) remain on single-factor authentication until a future budget cycle funds
  the full rollout. Some legacy systems (e.g., the shared PACS login already flagged
  elsewhere in this project) may need to be remediated separately before MFA can be
  meaningfully applied to them.
```

---

## Treatment Decision 6

yaml

```yaml
Gap ID: GAP-018
Gap Title: No automated account deprovisioning process exists tied to HR termination
  events
Risk Level: Critical (unchanged; this is the exact mechanism that let Beta's former
  employee retain access for 47 days)

Treatment Strategy: Mitigate

Justification: Like GAP-015 below, this is primarily a process fix rather than a
  technology purchase, which makes it one of the most cost-effective items in this
  entire treatment plan. An interim manual control can be implemented almost
  immediately while a longer-term automated integration is built.

If Mitigate:
  - Proposed Control(s): Administrative Preventive (a documented, mandatory
    HR-to-IT termination workflow, replacing the current single-point-of-failure
    "manager submits a ticket" process) plus Administrative Detective (a recurring,
    documented monthly review of dormant AD accounts as a compensating measure while
    full automation is built).
  - Estimated Cost: $1K–10K (targeting ~$3,000: mostly staff time to redesign the
    process and perform the monthly reviews, with a modest allowance for any scripting
    or integration work between HR's system and Active Directory)
  - Implementation Effort: Quick Win (<1 week) for the interim monthly review process;
    Short-term (<1 month) for a more automated HR-triggered workflow.
  - Expected Risk Reduction: High, at very low cost — this closes a gap that has
    already caused a real, documented breach at a comparable organization.

Trade-offs: The interim manual monthly review is a compensating measure, not a
  permanent fix. It depends on consistent follow-through, and MedDefense has already
  demonstrated a pattern of documented-but-unenforced processes elsewhere in this
  project (e.g., Sarah Park's "on the roadmap" response to the server room badge
  issue). This decision should include an explicit accountability owner, not just a
  process document.
```

---

## Treatment Decision 7

yaml

```yaml
Gap ID: GAP-015
Gap Title: No formal, tested incident response plan exists at any level of the
  organization
Risk Level: Critical (unchanged; Alpha's 11-day, improvised response is the direct
  real-world illustration of this gap's cost)

Treatment Strategy: Mitigate

Justification: This is a force-multiplier control — a documented, tested response plan
  improves MedDefense's outcome regardless of which other gap eventually gets
  exploited, making it one of the best returns on investment in this entire plan, and
  it is achievable almost entirely with existing staff time.

If Mitigate:
  - Proposed Control(s): Administrative Corrective — draft a formal incident response
    plan (built from the organization's own experience with the January ransomware
    incident, plus the incidents catalogued throughout this project), have it formally
    approved by James and executive leadership, and validate it with a tabletop
    exercise.
  - Estimated Cost: $1K–10K (targeting ~$4,000: the plan itself can be drafted
    in-house at near-zero direct cost; the estimate primarily covers external
    facilitation for a tabletop exercise)
  - Implementation Effort: Short-term (<1 month) to produce an initial, approved plan;
    testing and refinement continue on an ongoing basis beyond that.
  - Expected Risk Reduction: High, applied across every other risk in this
    organization — this does not prevent any specific incident, but it directly
    reduces the duration and cost of whichever incident happens next.

Trade-offs: Per Alpha's own lesson #5 ("an untested incident response plan is
  equivalent to no plan"), a plan that is written once and never exercised again
  provides a false sense of security. This must be treated as a recurring commitment
  (periodic re-testing), not a one-time deliverable, or its value will erode.
```

---

## Gaps not selected for this Fiscal Year

For transparency, the following Critical/High gaps from Tasks 12–13 are not funded in this cycle and should be carried forward:

- **GAP-002** (MRI compensating controls): The administrative and physical components (P-003, P-004 from Task 6) are low-cost and could be pursued as near-free quick wins in parallel with the funded items above; the technical components (P-001, P-002) should be evaluated once GAP-014's segmentation project establishes the underlying VLAN capability it depends on.
- **GAP-005** (no server-class antivirus/EDR): Deferred to next fiscal year; a phased rollout starting with the domain controllers and ehr-db-01/billing-srv-01 should be the first priority in that cycle.
- **GAP-007** (physical access to server room/network closet): Deferred; camera installation and badge differentiation are moderate-cost, non-IT-budget items that may be better suited to a facilities/security budget line rather than this technology-focused fund.
- **GAP-010** (undocumented/shadow devices): The highest-risk items here (investigating UNKNOWN-01, decommissioning the Raspberry Pi per Task 11) are near-zero-cost and should be pursued immediately using existing staff time in parallel with this plan, not treated as blocked by budget.
- **GAP-019** (no DLP) and **GAP-020** (unverified DMZ egress rules): GAP-020 specifically is a near-zero-cost verification task (reviewing the existing FortiGate configuration) and should also be done immediately in parallel; GAP-019 (DLP tooling) is deferred to next fiscal year as a technology purchase.

---

## Budget Summary

|#|Gap ID|Proposed Control|Estimated Cost|
|---|---|---|---|
|1|GAP-004|Open-source SIEM (Wazuh) deployment|$20,000|
|2|GAP-014|Network segmentation, Phase 1 (Central)|$35,000|
|3|GAP-006|Offsite/cloud backup replication (AWS S3)|$14,400|
|4|GAP-001|Medical device credential audit|$500|
|5|GAP-017|MFA rollout, Phase 1 (remote/privileged accounts)|$8,000|
|6|GAP-018|Account deprovisioning process + interim review|$3,000|
|7|GAP-015|Incident response plan + tabletop exercise|$4,000|
|||**Subtotal**|**$84,900**|
|||**Remaining budget**|**$35,100**|

**Total spend: $84,900 of $120,000 (71%).** This plan does not need to exceed the budget. It fits comfortably within it, with $35,100 remaining. Recommended use of the remainder:

- **~$25,000** as a down payment toward **GAP-005** (server antivirus/EDR), specifically licensing the highest-priority subset first (the domain controllers (ad-dc-01, ad-dc-02) and the 2 servers already compromised once each (billing-srv-01, and by extension ehr-db-01 given its network exposure)) rather than waiting a full year to start this gap.
- **~$3,000** toward the low-cost administrative and physical components of **GAP-002**'s MRI compensating strategy (P-003, P-004 from Task 6), which do not depend on the segmentation project's timeline.
- **~$7,100** held as contingency reserve, given that several of the estimates above (particularly the segmentation project and the SIEM deployment) are rough order-of-magnitude figures that commonly run over during implementation.

This approach deliberately leaves headroom rather than committing the full $120,000 to plans built on point-estimates. A disciplined, phased first year that funds fewer things well is a stronger foundation than a fully committed budget that funds everything poorly, especially given that several of the largest remaining gaps (full IoT segmentation, full server EDR, full MFA rollout) are explicitly scoped as multi-year efforts that this year's spending is meant to begin, not complete.
