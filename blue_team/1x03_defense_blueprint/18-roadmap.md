# MedDefense Health Systems: The 6-Month Roadmap

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** Sarah Park, IT Director, and James Chen, Deputy CISO **Source material:** The Budget Allocation (Task 8), Control Selection and Dependency Map (Task 11), Quick Wins (Task 13), Segmentation Architecture (Task 14), and Security Strategy (Task 17) **Purpose:** A strategy document says what. This document says when, who, and how you know it is done. This is the version meant to be pinned to the wall and checked off weekly.

---

## Month-by-Month Breakdown

```
MONTH 1
Actions:
  - Execute all 5 Quick Wins (Task 13): MFA enforcement on VPN and
    admin accounts, EHR database access restriction, infusion pump
    default credential rotation, USB mass storage GPO, initial
    Incident Response Plan draft.
  - Patch Apache on billing-srv-01, staged in a test environment first.
  - Patch CVE-2024-10441 on NAS-01, only after a verified backup-of-
    the-backup is confirmed.
  - Place purchase orders for EDR licensing, SIEM infrastructure,
    segmentation hardware, and the Westside enterprise firewall.
Owner: Security Analyst (quick win execution and coordination); Sarah
  Park (IT execution); James Chen (procurement approval)
Dependencies: None. This is the Foundation Layer and starts immediately
  upon Board approval, with every action able to proceed in parallel.
Completion Criteria: All 5 Quick Wins independently verified per Task
  13's own verification methods; Apache confirmed patched and the
  billing application confirmed functional; NAS-01 confirmed patched
  with the backup-of-backup on record; all Phase 2 purchase orders
  placed.
```

```
MONTH 2
Actions:
  - Complete Westside firewall installation and initial configuration.
  - Deploy the SIEM (Wazuh), onboarding log sources for the three
    Critical Assets first: the EHR system, the domain controller, and
    the backup infrastructure.
  - Begin EDR (Intercept X) rollout, servers first given GAP-005's
    documented role in MedDefense's only confirmed prior compromise.
  - Finalize the network segmentation architecture design, now that
    Westside's firewall configuration is known.
  - Draft the Identity and Access Management Policy and the Data
    Classification and Handling Policy.
Owner: Sarah Park (deployment execution); Security Analyst (SIEM tuning
  and policy drafting); James Chen (policy review)
Dependencies: Segmentation architecture cannot be finalized until
  Westside's firewall configuration (Month 1) is known, so that site
  becomes one consistent enforcement point rather than a separately
  designed one.
Completion Criteria: SIEM actively ingesting logs from all three
  Critical Assets; EDR deployed to 100% of servers; Westside firewall
  operational; segmentation architecture design document approved by
  James Chen.
```

```
MONTH 3
Actions:
  - Begin network segmentation build-out, starting with the Server
    VLAN, MedDefense's highest-priority zone.
  - Complete EDR rollout to all remaining workstations.
  - Establish offsite backup replication (AWS S3 Glacier).
  - Deploy the dedicated vendor-access jump-host with MFA and session
    logging.
  - Draft the Vendor and Third-Party Risk Management Policy.
Owner: Sarah Park (network build-out); Security Analyst (backup
  replication configuration, vendor policy drafting)
Dependencies: Segmentation build-out cannot begin until the Month 2
  design is finalized and approved. The vendor jump-host cannot be
  deployed until MFA (Month 1) is confirmed operational, since the
  jump-host's own security model depends on it.
Completion Criteria: Server VLAN live, with all 10 firewall rules from
  the segmentation design active and verified; EDR at 100% workstation
  coverage; offsite backup replication confirmed via an actual test
  restore, not just a configuration check; vendor jump-host operational
  with session logging confirmed functional.
```

```
MONTH 4
Actions:
  - Complete the remaining VLAN migrations: Clinical Workstation,
    Medical Device (including relocating WS-RAD-01, the MRI
    workstation, from its current, undocumented placement on the
    general workstation subnet), Management, Guest/IoT, and Corporate
    HQ.
  - Isolate the BD Alaris and Philips monitor fleets onto the Medical
    Device VLAN specifically.
  - Conduct the first SIEM-informed Incident Response Plan tabletop
    exercise.
Owner: Sarah Park (VLAN migration); James Chen (tabletop exercise
  facilitation); Clinical/Biomedical Engineering (medical device
  access coordination)
Dependencies: Every remaining VLAN migration depends on the Server
  VLAN (Month 3) being stable and validated first. Medical device
  isolation depends on the full segmentation architecture being live.
  The Incident Response tabletop exercise depends on the SIEM (Month 2)
  being operational, since a simulated incident needs real log data to
  test against, not just a document to read.
Completion Criteria: All 7 VLANs live with the full firewall rule set
  enforced organization-wide; a test scan from the Corporate HQ VLAN
  confirmed unable to reach the domain controller or the EHR database
  directly; WS-RAD-01 confirmed unreachable from outside its VLAN; the
  tabletop exercise completed with documented findings and plan
  revisions incorporated.
```

```
MONTH 5
Actions:
  - Run a full follow-up vulnerability scan, matching the original
    1x02 assessment's scope, to confirm the corrected findings.
  - Re-test Kill Chain 1 specifically to confirm it now breaks at the
    lateral-movement step, as designed in Task 14.
  - Finalize the Business Continuity and Disaster Recovery Policy.
  - Begin scoping the Year 2 priority identified in this program's Red
    Team exercise (Task 15): automated, HR-triggered account
    deprovisioning.
Owner: Security Analyst (validation testing and Year 2 scoping); James
  Chen (policy finalization)
Dependencies: The full validation pass depends on every Month 1-4
  control being deployed and stable. The Kill Chain re-test depends on
  the segmentation architecture (Month 3-4) being fully live.
Completion Criteria: The follow-up scan confirms Findings 001, 003,
  010, and 015 (and the others this program prioritized) are closed or
  materially reduced; the Kill Chain 1 re-test confirms containment at
  the domain-controller lateral-movement step; the Business Continuity
  Policy approved.
```

```
MONTH 6
Actions:
  - Conduct a second Red Team exercise, repeating Task 15's exact
    methodology, to test whether this year's program closed what it
    claimed to.
  - Finalize the Change Management Policy.
  - Compile a Month 1 versus Month 6 comparison of CIS Controls and
    NIST CSF scores for Board presentation.
  - Submit the formal Year 2 budget proposal, led by the GAP-018
    account-deprovisioning priority.
Owner: Security Analyst (red team exercise and comparison report);
  James Chen (Board presentation and budget proposal)
Dependencies: The second red team exercise depends on every Phase 2 and
  Phase 3 control being complete and stable. The Year 2 budget proposal
  depends directly on that exercise's findings.
Completion Criteria: Red team report delivered with residual risk
  formally re-rated against Task 15's original High rating; the
  CIS/NIST comparison document delivered to the Board; the Year 2
  budget proposal submitted before the current fiscal year closes.
```

---

## Dependency Chain

At least five real dependencies govern this roadmap's sequencing, not an arbitrary calendar order:

1. **Westside firewall installation (Month 1) must precede finalizing the full segmentation architecture (Month 2).** Westside's own enforcement point needs to be designed as part of the same architecture, not configured separately and bolted on afterward.
2. **The segmentation architecture (Month 2 design, Month 3-4 build-out) must precede Medical Device VLAN isolation (Month 4).** A dedicated medical device zone cannot exist before the broader VLAN architecture that contains it does.
3. **SIEM deployment (Month 2) must precede the Incident Response Plan tabletop exercise (Month 4).** A simulated incident needs real log data to test against meaningfully, not just a document to read.
4. **MFA deployment (Month 1) must precede the vendor-access jump-host (Month 3).** The jump-host's own security model depends on MFA already being operational, not a separate, parallel rollout built specifically for vendor access.
5. **The NAS-01 patch (Month 1) must precede establishing the isolated or offsite backup copy (Month 3).** Replicating a backup from an already-compromised source provides no protection at all.

---

## Milestones

**Milestone 1, End of Month 1: Foundation Complete.** All 5 Quick Wins verified, both priority patches (Apache, NAS-01) confirmed applied. _Measurable indicator: 100% of Task 13's own verification checks pass; zero open items from Month 1's action list carried into Month 2._

**Milestone 2, End of Month 2: Detection and Response Online.** The SIEM is live on every Critical Asset, EDR covers 100% of the server fleet, and the Westside firewall is operational. _Measurable indicator: SIEM dashboard confirms active log ingestion from 3 of 3 Critical Assets; EDR console confirms 100% server coverage._

**Milestone 3, End of Month 4: Segmentation Complete.** All 7 VLANs are live and enforced, including the corrected placement of the MRI workstation and full isolation of both medical device fleets. _Measurable indicator: an independent test scan from the Corporate HQ VLAN cannot reach the domain controller or the EHR database directly; WS-RAD-01 is confirmed unreachable from outside its own VLAN._

**Milestone 4, End of Month 6: Program Validated.** The follow-up vulnerability scan and second red team exercise are both complete, and the Year 2 budget proposal is submitted. _Measurable indicator: the follow-up scan confirms the program's targeted findings are closed; the red team exercise produces a formal, documented residual risk re-rating; the Year 2 proposal is submitted on schedule, before fiscal year close._

---

## Risk to Timeline

**The most likely cause of slippage: Clinical and Biomedical Engineering coordination delays.** Medical device credential changes and VLAN migration (Months 1 and 4) require scheduling around active patient care, a genuine, non-negotiable operational constraint already flagged directly in this program's own remediation work (1x02, Task 19). A device cannot simply be taken offline mid-procedure. **Contingency:** build an explicit two-week schedule buffer into Month 4's medical device work specifically, and sequence device access by priority, pumps and monitors currently out of active service first, deferring only in-service devices to the final, narrowest scheduling window rather than letting the entire migration slip waiting for full fleet availability at once.

**The second most likely cause of slippage: a real security incident consuming the two-person team's bandwidth mid-implementation.** James Chen and the Security Analyst are the same two people responsible for deployment, policy drafting, validation testing, and any actual incident response that arises during this six-month window; a single real incident could consume days this schedule has no slack to absorb. **Contingency:** the roadmap is deliberately sequenced so the highest-ALE-reduction controls (MFA, EHR database restriction, segmentation) land in Months 1 through 3, meaning even if Months 4 through 6 slip due to an incident diversion, the majority of this program's quantified risk reduction is already locked in before any delay could occur. A standing rule governs this roadmap directly: if a real incident occurs, the current phase's validation and testing activities extend by the length of the diversion rather than being compressed or skipped to protect the calendar date.
