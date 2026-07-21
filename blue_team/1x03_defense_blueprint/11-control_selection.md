# MedDefense Health Systems: The Control Selection

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO **Source material:** The Risk Register (Task 10), the CIS Controls Audit (Task 2), the NIST CSF Mapping (Task 1), and the Cost-Benefit Analysis (Task 7) **Purpose:** The Risk Register established what risks exist. This document decides, risk by risk, exactly which control closes each one, mapped to a recognized framework so an auditor can verify the decision, not just trust it.

**All 10 risks in the register carry a "Mitigate" treatment decision, so all 10 receive a control selection below.**

---

yaml

```yaml
Risk: RISK-001 (Ransomware via VPN gateway)
Selected Control: Network Segmentation (server, workstation, medical
  device, and guest VLANs) combined with MFA enforcement on VPN and
  administrative access
CIS Control Mapping: Control 12, Safeguard 12.2 (establish and maintain
  a secure network architecture); Control 6, Safeguards 6.3 and 6.4
  (require MFA for externally-exposed applications and remote access)
NIST CSF Mapping: PR.IR (Technology Infrastructure Resilience); PR.AA
  (Identity Management, Authentication, and Access Control)
Control Type: Compensating (segmentation contains blast radius rather
  than preventing entry) and Preventive (MFA blocks unauthorized
  authentication directly)
Control Category: Technical
Implementation Cost: $40,000 (segmentation) plus $2,000 (MFA), $42,000
  combined (Task 7, Controls 1 and 2)
Expected Risk Reduction: Segmentation alone reduces ALE from $2,864,400
  to $1,002,540 (Task 6); MFA, evaluated independently against the same
  baseline, reduces it to $1,432,200 (Task 7). The two controls have not
  been mathematically stacked in this program's prior work, and that
  gap is stated directly rather than implying a combined figure this
  analysis cannot yet support.
Dependencies: None to begin; both controls can start immediately in
  parallel. Full segmentation architecture should be finalized after
  the Westside firewall replacement (RISK-010) is scoped, so Westside's
  new enforcement point is designed as part of the same architecture
  rather than bolted on afterward.
```

yaml

```yaml
Risk: RISK-002 (EHR database network-wide exposure)
Selected Control: Restrict pg_hba.conf to accept connections only from
  ehr-srv-01, enforced with a host-based firewall rule on ehr-db-01
CIS Control Mapping: Control 4, Safeguard 4.6 (securely manage
  enterprise assets and software)
NIST CSF Mapping: PR.PS (Platform Security); PR.AA (Identity Management,
  Authentication, and Access Control)
Control Type: Preventive
Control Category: Technical
Implementation Cost: $500 (Task 6, Task 7)
Expected Risk Reduction: ALE reduced from $4,083,750 to $816,750 (Task
  6), the largest absolute ALE reduction of any single control in this
  program.
Dependencies: None. This control can be implemented immediately and
  independently of the broader network segmentation project, since it
  is a configuration change on the database itself rather than a
  network architecture change.
```

yaml

```yaml
Risk: RISK-003 (Ransomware entry via billing-srv-01 Apache)
Selected Control: Patch Apache to version 2.4.52 or later, closing both
  Finding 001 and the chained Finding 002
CIS Control Mapping: Control 7, Safeguard 7.4 (perform automated
  application patch management)
NIST CSF Mapping: PR.PS (Platform Security)
Control Type: Corrective
Control Category: Technical
Implementation Cost: $5,000 (Task 6, Task 7)
Expected Risk Reduction: ALE reduced from $137,170 to $47,300 (Task 6)
Dependencies: None directly, though this program's own remediation
  sequencing (1x02, Task 19) recommends staging this patch in a test
  environment first, since billing-srv-01's application compatibility
  with the newer Apache version is unconfirmed.
```

yaml

```yaml
Risk: RISK-004 (Backup infrastructure compromise)
Selected Control: Patch CVE-2024-10441 on NAS-01, combined with an
  isolated, immutable backup copy (either on-premises or via offsite
  cloud replication)
CIS Control Mapping: Control 7, Safeguard 7.4 (patch management);
  Control 11, Safeguard 11.4 (establish and maintain an isolated
  instance of recovery data)
NIST CSF Mapping: RC.RP (Incident Recovery Plan Execution)
Control Type: Corrective (the patch) and Compensating (the isolated
  copy, since it does not prevent compromise of the primary device, it
  ensures a clean recovery point survives it)
Control Category: Technical
Implementation Cost: $13,000 for the on-premises isolated-copy path
  (Task 6) or $4,000 for the offsite cloud replication alternative (Task
  7, Control 4); either satisfies this control's intent
Expected Risk Reduction: ALE reduced from $272,500 to $40,875 (on-
  premises path, Task 6) or to $27,250 (offsite path, Task 7)
Dependencies: The CVE-2024-10441 patch should be applied before or
  alongside establishing the isolated copy, not after; an isolated
  backup replicated from an already-compromised source provides no
  protection.
```

yaml

```yaml
Risk: RISK-005 (BD Alaris infusion pump compromise)
Selected Control: Default credential change fleet-wide, combined with
  network isolation restricting pump traffic to clinical workstations
  and the PACS server only
CIS Control Mapping: Control 5, Safeguard 5.2 (use unique passwords);
  Control 12, Safeguard 12.2 (secure network architecture)
NIST CSF Mapping: PR.AA (Identity Management, Authentication, and Access
  Control); PR.PS (Platform Security)
Control Type: Preventive (credential change) and Compensating (network
  isolation, since the underlying firmware vulnerability remains
  unpatched)
Control Category: Technical
Implementation Cost: $3,200 (Task 6)
Expected Risk Reduction: ALE reduced from $70,000 to $17,000 (Task 6)
Dependencies: Network isolation for the medical device VLAN depends on
  the broader Network Segmentation project (RISK-001's control) having
  at least its VLAN architecture defined first; the credential change
  itself has no dependency and should proceed immediately regardless of
  segmentation timing.
```

yaml

```yaml
Risk: RISK-006 (MRI workstation, WS-RAD-01)
Selected Control: Dedicated medical device VLAN restricting WS-RAD-01's
  traffic to the PACS server only, the top-priority compensating control
  already proposed in 0x00 (Task 6) and still not implemented
CIS Control Mapping: Control 12, Safeguard 12.2 (secure network
  architecture)
NIST CSF Mapping: PR.IR (Technology Infrastructure Resilience)
Control Type: Compensating (a true preventive patch is permanently
  impossible given this system's end-of-life status)
Control Category: Technical
Implementation Cost: Included within Control 1's $40,000 network
  segmentation project (Task 7); not separately budgeted, since this is
  one enforcement point within the same architecture rather than a
  standalone build
Expected Risk Reduction: Not separately quantified in Task 5 or Task 6;
  this gap is stated directly, consistent with how this risk is
  documented in the Risk Register itself (Task 10)
Dependencies: Directly depends on the broader Network Segmentation
  project (RISK-001's control); this specific VLAN cannot be built
  before the overall segmentation architecture exists.
```

yaml

```yaml
Risk: RISK-007 (Negligent insider data exposure)
Selected Control: Group Policy Object restricting USB mass storage
  devices fleet-wide across all clinical workstations, combined with
  mandatory security awareness training on data handling
CIS Control Mapping: Control 10, Safeguard 10.3 (disable autorun and
  autoplay for removable media); Control 14, Safeguard 14.4 (train
  workforce on data handling best practices)
NIST CSF Mapping: PR.DS (Data Security); PR.AT (Awareness and Training)
Control Type: Preventive (the GPO) and Administrative (the training)
Control Category: Technical (GPO) and Administrative (training)
Implementation Cost: Approximately $3,000 for GPO deployment and testing
  across the workstation fleet (reused from 1x02, Task 20's own USB
  restriction cost estimate); training cost not separately itemized in
  this program's cost-benefit work, stated directly as a gap rather than
  an invented figure
Expected Risk Reduction: Not separately recalculated with a formal
  control-adjusted ALE in Task 6 or Task 7; qualitatively expected to
  reduce this risk's ARO substantially once the technical enabler is
  closed, though the human behavior component means this risk cannot be
  fully eliminated by a technical control alone
Dependencies: None. This control can be deployed immediately and
  independently of every other control in this document.
```

yaml

```yaml
Risk: RISK-008 (Absence of incident response plan)
Selected Control: Draft and formally exercise a documented incident
  response plan, including designated incident-handling personnel and
  maintained reporting contact information
CIS Control Mapping: Control 17, Safeguards 17.1 and 17.2 (designate
  personnel to manage incident handling; establish and maintain contact
  information for reporting)
NIST CSF Mapping: RS.MA (Incident Management)
Control Type: Corrective, in the sense that it improves the organization's
  response after an incident begins, and Administrative by nature
Control Category: Administrative
Implementation Cost: Not separately costed in Task 7's eight-control
  analysis; this program's own NIST CSF Mapping (Task 1) characterized
  this as primarily a documentation and process exercise achievable
  without significant capital cost, an honest qualitative estimate
  rather than an invented dollar figure
Expected Risk Reduction: Not separately quantified; this risk functions
  as an amplifier across the rest of the register rather than an
  independently scored event, consistent with how GAP-015 has been
  treated throughout this program (Task 3)
Dependencies: The plan itself can be drafted independently of every
  other control in this document, but meaningfully testing it through a
  tabletop exercise benefits from at least basic logging capability
  existing first (a SIEM, Task 7 Control 3, though not itself tied to a
  specific risk in this register), so a simulated incident has real data
  to work from.
```

yaml

```yaml
Risk: RISK-009 (Vendor access compromise, MedTech Solutions)
Selected Control: A dedicated vendor-access jump-host or bastion
  requiring MFA and full session logging, combined with a formal service
  provider management policy
CIS Control Mapping: Control 15, Safeguards 15.1 and 15.2 (establish and
  maintain an inventory of service providers; establish and maintain a
  service provider management policy); Control 6, Safeguard 6.4 (require
  MFA for remote network access)
NIST CSF Mapping: GV.SC (Cybersecurity Supply Chain Risk Management);
  PR.AA (Identity Management, Authentication, and Access Control)
Control Type: Preventive (the jump-host and MFA) and Administrative (the
  policy)
Control Category: Technical and Administrative
Implementation Cost: Not separately costed in Task 7's eight-control
  analysis; this program's original recommendation (1x01, Task 5) did
  not attach a specific dollar figure, a gap stated directly rather than
  filled with an unsupported estimate
Expected Risk Reduction: Not separately quantified; qualitatively
  expected to substantially reduce this risk's likelihood once vendor
  sessions are isolated and logged independently of MedDefense's own
  network
Dependencies: This control depends directly on MFA Deployment (RISK-
  001's control) being operational first; a vendor jump-host's security
  model relies on MFA already functioning, not on a parallel, separate
  MFA rollout built specifically for vendors.
```

yaml

```yaml
Risk: RISK-010 (Westside consumer router compromise)
Selected Control: Replace the consumer-grade router with a dedicated
  enterprise-grade firewall
CIS Control Mapping: Control 12, Safeguards 12.2 and 12.3 (secure
  network architecture; securely manage network infrastructure)
NIST CSF Mapping: PR.IR (Technology Infrastructure Resilience)
Control Type: Preventive
Control Category: Technical and Physical (hardware replacement)
Implementation Cost: $1,800 annualized (Task 7, Control 6)
Expected Risk Reduction: ALE reduced from $450,000 to $90,000 (Task 7)
Dependencies: None to begin equipment procurement and installation, but
  as noted under RISK-001, this device's final configuration should be
  finalized as part of the broader Network Segmentation architecture
  rather than configured in isolation, so Westside's site becomes one
  consistent enforcement point rather than a separately-designed one.
```

---

## Control Dependency Map

```
FOUNDATION LAYER (no prerequisites, can begin immediately, in parallel)
  |
  |-- MFA Deployment (RISK-001)
  |-- pg_hba.conf Restriction (RISK-002)
  |-- Apache Patch (RISK-003)
  |-- CVE-2024-10441 Patch on NAS-01 (RISK-004, technical prerequisite
  |     for the isolated copy below)
  |-- Default Credential Change, BD Alaris (RISK-005)
  |-- USB Mass Storage GPO (RISK-007)
  |-- Incident Response Plan Drafting (RISK-008, the drafting itself,
  |     not the tabletop test)
  |-- Westside Firewall Procurement/Install (RISK-010, procurement can
        start now; final configuration is deferred, see below)

LAYER 2 (depends on Foundation Layer items above)
  |
  |-- Isolated/Immutable Backup Copy (RISK-004)
  |     requires: CVE-2024-10441 Patch (Foundation Layer)
  |     reason: replicating from an already-compromised source
  |              provides no protection
  |
  |-- Vendor Access Jump-Host with MFA (RISK-009)
  |     requires: MFA Deployment (Foundation Layer)
  |     reason: the jump-host's security model depends on MFA already
  |              being operational, not a separate parallel rollout
  |
  |-- Network Segmentation, full architecture (RISK-001, RISK-006)
        requires: Westside Firewall configuration finalized
                  (Foundation Layer, install can start in parallel,
                  but final config waits for the architecture design)
        reason: Westside's enforcement point should be designed as
                 part of the same architecture, not bolted on after

LAYER 3 (depends on Layer 2 / Network Segmentation specifically)
  |
  |-- Medical Device VLAN Isolation, BD Alaris (RISK-005's network
  |     isolation component)
  |     requires: Network Segmentation architecture (Layer 2)
  |
  |-- Dedicated MRI VLAN (RISK-006)
        requires: Network Segmentation architecture (Layer 2)

LAYER 4 (depends on detection capability existing, tracked outside
  this register but relevant to sequencing)
  |
  |-- Incident Response Plan Tabletop Testing (RISK-008)
        requires: basic logging/SIEM capability (Task 7, Control 3,
                  not itself tied to a specific risk in this register)
        reason: a simulated incident needs real log data to test
                 against meaningfully, not just a document to read
```

**Reading this map in practice:** the Foundation Layer represents roughly eight controls MedDefense can begin the same week, none blocked by any other. The two genuine architectural dependencies worth flagging to James Chen directly are that Network Segmentation should not be finalized until Westside's new firewall is scoped as part of the same design, and that the two medical device VLANs (BD Alaris and the MRI) cannot be built before that segmentation architecture exists, meaning RISK-005 and RISK-006's full protection realistically lands a phase after their own credential and patch-level fixes, not simultaneously with them.
