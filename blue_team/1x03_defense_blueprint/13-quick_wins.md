# MedDefense Health Systems: The Quick Wins

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** The Risk Register (Task 10) and Control Selection (Task 11), filtered specifically for what MedDefense can execute this week with what it already has **Purpose:** The 6-month roadmap and the $95,800 budget request take time to move through approval and procurement. These five actions do not. Every one below uses existing licensing, existing staff, and existing infrastructure, requires no purchase order, and can be complete within 14 days.

---

vbnet

```vbnet
Quick Win #1: Enforce MFA on VPN and Administrative Accounts
Risk Addressed: RISK-001, RISK-009
Action:
  Day 1-2: Confirm Entra ID Conditional Access licensing is active
    (already included in MedDefense's existing O365 E3 subscription,
    no additional purchase required).
  Day 2-3: Enable an MFA enforcement policy covering all VPN/remote
    access accounts and all accounts holding administrative privileges.
  Day 3-5: Notify affected staff directly, provide setup instructions,
    and open a help desk support window for enrollment questions.
  Day 5-10: Monitor enrollment daily, follow up individually with any
    account not yet enrolled.
  Day 10-14: Set a hard enforcement date and disable password-only
    fallback for every VPN and administrative account.
Owner: Sarah Park, IT Director (execution); James Chen, Deputy CISO
  (accountable)
Timeline: 14 days
Cost: $0. MFA capability is already included in MedDefense's existing
  O365 E3 licensing; the only cost is staff configuration time.
Risk Reduction: Directly breaks the credential-based entry and lateral
  movement steps behind Kill Chain 1 (1x01), the mechanism RISK-001's
  VPN gateway risk depends on, and closes the specific authentication
  gap RISK-009's vendor jump-host control also depends on.
Verification: Pull an Entra ID sign-in report confirming 100% of VPN
  and administrative accounts show MFA-satisfied sign-ins over the prior
  7 days; attempt one test login using only a known password and confirm
  it is rejected without a second factor.
```

vbnet

```vbnet
Quick Win #2: Restrict EHR Database Network Access
Risk Addressed: RISK-002
Action:
  Day 1: Confirm ehr-srv-01's exact IP address and check with IT
    whether any other legitimate system currently needs direct database
    access.
  Day 2-3: Edit pg_hba.conf on ehr-db-01 to restrict the existing
    10.10.0.0/16 entry to ehr-srv-01's specific address only.
  Day 3: Add a host-based firewall rule on ehr-db-01 dropping any
    connection attempt to port 5432 from any other source.
  Day 4: Test the EHR application end to end to confirm no disruption
    to clinical use.
  Day 5-7: Monitor firewall logs daily for unexpected drop events that
    might indicate a legitimate access path was missed.
Owner: IT database administrator (Sarah Park's team), verified by the
  Security Analyst
Timeline: 7 days
Cost: $0. This is a configuration change to software already running;
  no new licensing or hardware is involved.
Risk Reduction: Closes the exposure path shared by Kill Chains 1, 3,
  and 5 (1x01), the "any host on the network can directly query the
  complete patient database" step common to all three, and directly
  addresses the single most frequently referenced gap in this program's
  own cross-project correlation work.
Verification: From a test workstation other than ehr-srv-01, attempt a
  connection to port 5432 on ehr-db-01 and confirm it is refused; confirm
  the EHR application itself continues to function normally for clinical
  staff.
```

vbnet

```vbnet
Quick Win #3: Change Default Credentials on the Infusion Pump Fleet
Risk Addressed: RISK-005
Action:
  Day 1: Coordinate with Clinical/Biomedical Engineering to schedule
    brief access windows for each pump, avoiding devices in active
    clinical use.
  Day 2-5: Change the default admin/admin web interface credentials,
    starting with the 7 pumps already confirmed vulnerable in this
    program's scan, then extending across the estimated 120-pump fleet.
  Day 5: Record every new credential in a secure, shared password
    vault accessible to authorized Biomedical Engineering staff, not
    known only to whoever performed the change.
  Day 6-10: Complete credential rotation across the remaining fleet,
    Central first, then Westside.
  Day 10-14: Spot-check a random sample of pumps to confirm the
    default credentials no longer work anywhere in the fleet.
Owner: Clinical/Biomedical Engineering, with the Security Analyst
  providing the credential vault and documentation process
Timeline: 14 days for full fleet coverage
Cost: $0. This uses existing staff time only; no purchase is required.
Risk Reduction: Removes the specific, no-skill entry technique behind
  RISK-005, directly closing the exact vulnerability this program's own
  scan confirmed present on 100% of the pumps it was able to reach.
Verification: Attempt to log into a sample of pumps using the old
  default admin/admin credentials and confirm access is denied; confirm
  every new credential is recorded in the shared vault.
```

vbnet

```vbnet
Quick Win #4: Deploy USB Mass Storage Restriction via Group Policy
Risk Addressed: RISK-007
Action:
  Day 1-2: Draft a Group Policy Object restricting USB mass storage
    device installation, using Windows' built-in device restriction
    policy, no new software required.
  Day 3-4: Test the GPO on a small pilot group of non-clinical
    workstations to confirm no disruption to legitimate business
    functions.
  Day 5-7: Identify any legitimate USB use cases (specific diagnostic
    equipment, for example) and build a narrow, documented exception
    list before wider rollout.
  Day 8-12: Roll the GPO out to all approximately 280 clinical
    workstations through the Active Directory infrastructure already
    in place.
  Day 13-14: Run a Group Policy Results report confirming successful
    application across the target workstation population.
Owner: Sarah Park, IT Director, executed by IT systems administration
Timeline: 14 days
Cost: $0. This uses the Active Directory infrastructure MedDefense
  already operates; no new licensing is required.
Risk Reduction: Closes the primary technical enabler behind RISK-007,
  the negligent insider exposure this program's own Insider File
  analysis (1x01) already identified as a documented, real pattern, not
  a theoretical one.
Verification: Attempt to connect a USB storage device to a workstation
  within the deployed scope and confirm it is blocked; confirm the Group
  Policy Results report shows successful application across the
  workstation population.
```

vbnet

```vbnet
Quick Win #5: Draft an Initial Incident Response Plan
Risk Addressed: RISK-008
Action:
  Day 1-2: Start from the SANS incident response plan template (a free,
    publicly available resource) as the base structure.
  Day 3-5: Populate designated incident-handling personnel (James Chen
    as primary, Sarah Park as technical lead, a defined escalation path
    to the CEO for reportable incidents) and current contact information
    for internal and external reporting, including legal counsel, the
    cyber insurance carrier, and the HHS breach portal.
  Day 6-9: Document MedDefense-specific containment steps for its
    highest-priority scenarios, ransomware and EHR data exposure,
    drawing directly on the kill chains already built in this program.
  Day 10-12: Circulate the draft for review by James Chen, Sarah Park,
    and the relevant Department Heads.
  Day 13-14: Finalize Version 1.0, distributed formally and stored in
    at least one location accessible even if primary systems are down
    (a printed copy and an offline digital copy).
Owner: Security Analyst drafts; James Chen reviews and finalizes
Timeline: 14 days for a Version 1.0 document (a full tabletop exercise
  is a separate, later activity, not part of this quick win)
Cost: $0. This uses a free, publicly available template and internal
  labor only.
Risk Reduction: Directly addresses the amplifying gap behind RISK-008:
  if any other risk in this register materializes during the next two
  weeks, MedDefense responds according to a documented plan rather than
  repeating the ad hoc misdiagnosis that let the billing-srv-01
  cryptominer persist undetected (0x00, Task 2).
Verification: Confirm a signed-off Version 1.0 document exists, is
  stored in at least one offline-accessible location, and that every
  designated incident-handling person has confirmed receipt and
  understands their assigned role.
```

---

## Why Quick Wins Matter Beyond Their Immediate Risk Reduction

Quick wins serve a purpose in the first month of a security program that has little to do with the specific risks they close, real as that reduction is. A program that spends its first month entirely on analysis, frameworks, risk registers, and budget requests risks looking, to a Board and a CFO who have already asked hard questions once, like a program that only produces documents. These five actions prove the opposite before the first dollar of the larger budget is even spent: they demonstrate that James Chen's team can execute, not just diagnose, and that momentum exists independent of whether the $95,800 request clears every approval hurdle on schedule. They also build organizational trust in the right order, introducing MFA, a USB policy, and tighter access controls gradually and visibly over two weeks builds staff familiarity and reduces resistance in a way that rolling all of it out simultaneously alongside a large capital project never could. Most practically, for a two-person security team facing a six-month roadmap that can feel unending, five completed, verified actions in the first two weeks is concrete proof of progress, the kind of evidence that keeps a small team's own confidence and the Board's confidence moving in the same direction at the exact moment both are most fragile.
