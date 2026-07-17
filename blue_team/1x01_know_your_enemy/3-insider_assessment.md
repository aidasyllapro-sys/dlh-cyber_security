# MedDefense Health Systems: The Insider File - 5-Scenario Analysis

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** MedDefense environment scenarios, cross-referenced against Project 0x00's Control Matrix (`10-complete_control_matrix.md`), Gap Analysis (`12-gap_analysis.md`, `13-reality_check.md`, `15-predecessor_review.md`), Shadow IT findings (`11-shadow_systems.md`), and the Threat Actor Taxonomy (Task 1 of this project) **Purpose:** Distinguish malicious from negligent insider behavior across five real MedDefense scenarios, identify the behavioral indicators that could have flagged each one before harm occurred, and connect each scenario back to a specific, already-documented control gap.

---

## Scenario 1: The Shared Login

```
Classification: Negligent — this is a systemic operational practice, not an
  act of individual malice. No single person set out to cause harm; the
  department adopted a workflow shortcut (shared credentials for speed)
  that happens to create an environment where malicious OR accidental
  misuse would be equally undetectable and unattributable to anyone.
Behavioral Indicators:
  1. Simultaneous or overlapping login sessions under the same account
     from different physical workstations at the same time — physically
     impossible for a single technician.
  2. Access timestamps that don't correlate with any individual's known
     shift schedule or badge-in/badge-out record.
  3. A sustained pattern of zero individual logouts between patients,
     visible simply by reviewing session duration logs over any given day.
Existing Control (from 1x00): None specific to this practice. C-007
  (password policy) governs password complexity/rotation but explicitly
  permits shared accounts "when individual accounts are not technically
  feasible" — it does not prevent or flag this use case.
Gap Exploited (from 1x00): GAP-022 (Shared login credentials on the PACS
  workstation eliminate individual accountability), identified from
  Marcus Webb's draft assessment in Task 15.
Recommended Mitigation: Technical — badge or proximity-card fast-login
  authentication for PACS workstations, preserving the department's
  legitimate speed requirement (Radiology's stated objection to
  individual logins) while restoring per-user accountability.
```

## Scenario 2: The Ghost Account

```
Classification: Malicious (the account remaining active is a negligent
  process failure, but the observed usage — three off-hours
  authentications occurring after the contract's end date — is
  deliberate, unauthorized activity, not an accident). This shares the
  same underlying theme as Incident F from the 1x00 incident analysis:
  an unmonitored presence persisting on the network for an extended
  period purely because nothing was watching for it, not because it was
  sophisticated.
Behavioral Indicators:
  1. Any authentication event occurring after a recorded contract/
     termination end date should be an automatic, non-negotiable flag.
  2. Off-hours access timing (outside any pattern consistent with
     legitimate business need for a role that no longer exists).
  3. No corresponding support ticket, change request, or business
     justification tied to any of the three sessions.
Existing Control (from 1x00): None. Account lockout (C-008) protects
  against failed-password guessing, but nothing in the Control Matrix
  ties account status to contract or employment status.
Gap Exploited (from 1x00): GAP-018 (No automated account deprovisioning
  process tied to HR/contract termination events) — the exact mechanism
  that, per Task 13's real-world breach validation, already caused a
  documented 47-day unauthorized access incident at a comparable
  organization.
Recommended Mitigation: Administrative + Technical — an automated
  deprovisioning workflow triggering immediate account disablement on
  the contract end date (integrated with HR/procurement records), paired
  with a technical alert on any authentication attempt against a
  disabled or expired account.
```

## Scenario 3: The Personal NAS

```
Classification: Negligent — explicitly confirmed in the Task 11 shadow
  IT assessment as motivated by operational convenience (a legitimate
  complaint that the official shared drive was too slow), not by any
  intent to harm or profit.
Behavioral Indicators:
  1. An unregistered device (unrecognized hostname/MAC address)
     appearing during any network discovery scan — exactly how the two
     other undocumented devices in this environment were first found
     during the Project 0x00 network scan.
  2. Sustained data flows to/from a device that does not appear in the
     asset inventory.
  3. A recurring IT support complaint about shared-drive performance
     from a specific department, which — if tracked — is itself a signal
     that a workaround is being considered or already in use.
Existing Control (from 1x00): None. This device was entirely outside
  every one of the 17 controls in the Complete Control Matrix prior to
  its discovery.
Gap Exploited (from 1x00): The Task 11 shadow IT finding (Dr. Patel's
  Personal NAS, added to the Asset Registry as a Shadow IT-status asset)
  — enabled by the absence of any network access control restricting
  which devices can obtain connectivity in the first place.
Recommended Mitigation: Technical — port-level network access control
  (802.1X or equivalent) restricting network connectivity to registered,
  authorized devices only, combined with the periodic asset-discovery
  scanning already demonstrated as effective in the Project 0x00 network
  scan.
```

## Scenario 4: The Curious Employee

```
Classification: Malicious — not for financial gain, but this fits the
  "curiosity-driven unauthorized access" insider subtype named explicitly
  in the Task 0 intelligence dossier (HC3 source: "celebrity snooping").
  Accessing a record with no legitimate registration or care-related
  reason is a deliberate policy violation, regardless of the absence of
  a profit motive — and the outcome (a friend posting the visit on social
  media) confirms real-world harm resulted.
Behavioral Indicators:
  1. Record access with no corresponding registration, scheduling, or
     billing task assigned to that employee for that patient.
  2. A single, isolated record view outside the employee's normal daily
     access pattern (volume, patient assignment, or work queue).
  3. No follow-on administrative action (no scheduling update, no
     billing entry) after the record was opened — a view with no
     legitimate workflow purpose attached.
Existing Control (from 1x00): Partial. C-016 (EHR vendor-managed audit
  log) technically records this access, but per the Control Matrix
  effectiveness rating, it is not proactively reviewed — the access
  would only surface after a complaint, exactly the same pattern
  identified as the core lesson of the Beta breach in Task 13 ("logs
  without review are security theater").
Gap Exploited (from 1x00): GAP-004 (no centralized detection/alerting,
  meaning no anomaly-based access monitoring exists on the EHR) combined
  with GAP-009 (no periodic compliance/access review process to catch
  this kind of access pattern proactively).
Recommended Mitigation: Technical — "break-the-glass" access flagging on
  designated VIP/high-profile patient records with automatic real-time
  alerting on access, combined with an Administrative periodic audit-log
  review process rather than relying solely on after-the-fact complaints.
```

## Scenario 5: The Overworked Admin

```
Classification: Negligent — a workload-driven shortcut with no intent to
  cause harm, but a reckless handling of the organization's most
  privileged credentials (Active Directory admin access).
Behavioral Indicators:
  1. Plaintext credential-pattern files appearing on an endpoint's local
     file system, detectable by content-aware endpoint scanning.
  2. An undocumented script or tool interacting with Active Directory
     admin functions outside of any recorded change request.
  3. Outbound or internal email containing credential-like content or
     script attachments, detectable by content inspection on mail flow.
Existing Control (from 1x00): None. Neither the password policy (C-007)
  nor account lockout (C-008) addresses how privileged credentials are
  stored or shared once obtained.
Gap Exploited (from 1x00): GAP-025 (No formal change management process)
  — this script is functionally identical in nature to the untested,
  undocumented cron job change that caused the backup failure behind
  Incident A, just applied to identity infrastructure instead of backup
  infrastructure — combined with GAP-019 (No DLP controls), which is why
  neither the plaintext file nor the email sharing it would be detected.
Recommended Mitigation: Technical — a Privileged Access Management (PAM)
  solution that removes the need for any administrator to handle or
  store AD admin credentials directly at all, combined with an
  Administrative change-management requirement for any script or
  automation touching privileged accounts.
```

---

## Pattern Assessment

4 of these 5 scenarios do not represent 5 unrelated weaknesses. They are the same handful of already-documented Project 0x00 gaps (GAP-004, GAP-009, GAP-018, GAP-019, GAP-025) surfacing through a different vector. The systemic weakness that makes insider threats particularly dangerous at MedDefense is not that insiders are hard to defend against in principle. It is that the organization's near-total absence of detective capability, identified in Task 5 and Task 12 as the single most concentrated weakness across the entire control environment, was built almost entirely with an external attacker in mind (perimeter firewall, VPN rules, antivirus). An insider does not need to defeat any of those controls, because they already hold legitimate credentials which means the only thing that could catch misuse is exactly the detective and account-lifecycle capability MedDefense does not have. This is compounded by the administrative gaps found in Task 15 (no formal change management, no automated deprovisioning): an organization that cannot reliably track who has access, whether that access is still appropriate, or what changes are being made to its own systems has no realistic way to distinguish an employee's legitimate broad clinical access from that same access being misused, negligently or otherwise.
