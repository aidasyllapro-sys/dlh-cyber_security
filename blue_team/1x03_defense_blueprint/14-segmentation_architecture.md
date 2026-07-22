# MedDefense Health Systems: The Segmentation Architecture

**Prepared by:** Aïda Sylla, Security Analyst **Prepared for:** James Chen, Deputy CISO, and Sarah Park, IT Director **Source material:** The flat network (GAP-014) already confirmed as the single most-referenced weakness across every prior project of this program, appearing in the majority of kill chains built in 1x01 and amplifying nearly every finding in 1x02 **Purpose:** This is a design exercise, not an assessment. The zones, rules, and traffic flows below describe an architecture that does not yet exist, built specifically to close the one weakness this entire program has independently identified more often than any other.

---

## Part 1: Zone Definition

**A note on the existing IP scheme:** MedDefense's current addressing already groups assets into logical /24 subnets (servers, workstations, medical devices, sites), but nothing enforces those boundaries today; a device on any subnet can reach any other device on any other subnet. This design formalizes those existing boundaries into real, firewalled VLANs, corrects one specific documented error (WS-RAD-01, the MRI workstation, currently sits on the general workstation subnet rather than with other medical devices), and adds two new zones that do not exist in any form today.

```
Zone 1: Server VLAN (VLAN 10)
IP Range: 10.10.2.0/24
Systems: ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, ad-dc-02,
  NAS-01, backup-srv-01, print-srv-01, pacs-srv-01, web-srv-01,
  file-srv-01
Allowed Outbound: To Medical Device VLAN, restricted to DICOM/HL7
  application ports only (pacs-srv-01 and ehr-srv-01 specifically); to
  Management VLAN, for patch and monitoring agent traffic; to the
  internet, restricted to a defined patch/update proxy only, no general
  browsing
Allowed Inbound: From Clinical Workstation VLAN, restricted to
  application ports only (443 to the EHR and patient portal, never
  direct database ports); from Management VLAN, for administration and
  monitoring; from Medical Device VLAN, restricted to DICOM/HL7 ports
  to pacs-srv-01 and ehr-srv-01 only. Explicitly not open to any zone
  on database ports (5432, 3306) or backup infrastructure ports except
  from Management.
```

```
Zone 2: Clinical Workstation VLAN (VLAN 20)
IP Range: 10.10.1.0/24
Systems: Nurse station workstations, physician workstations, reception
  workstations at Central
Allowed Outbound: To Server VLAN, application ports only (443 to
  EHR/patient portal); to Medical Device VLAN, restricted read-only
  imaging retrieval ports; to the internet, filtered web and email
  traffic through a proxy
Allowed Inbound: From Management VLAN only, for patching and help desk
  support. Explicitly not reachable from Medical Device VLAN,
  Guest/IoT VLAN, or any other site directly.
```

```
Zone 3: Medical Device VLAN (VLAN 30)
IP Range: 10.10.3.0/24
Systems: Philips IntelliVue monitors, BD Alaris infusion pumps,
  WS-RAD-01 (the MRI workstation, moved into this zone from its current
  location on the general workstation subnet), PACS-connected imaging
  equipment
Allowed Outbound: To Server VLAN only, restricted to pacs-srv-01 (DICOM,
  ports 4242 and 11112) and ehr-srv-01 (HL7, port 2575). No internet
  access under any circumstance; no medical device has a legitimate
  reason to reach the internet directly.
Allowed Inbound: From Server VLAN only, restricted to the same DICOM/HL7
  ports, for the PACS retrieval workflow. Explicitly not reachable
  directly from the Clinical Workstation VLAN; clinical staff view
  imaging and monitoring data through the PACS and EHR applications, not
  by reaching devices on this VLAN directly.
```

```
Zone 4: Management VLAN (VLAN 40) [NEW]
IP Range: 10.10.4.0/24
Systems: IT administrator workstations, security tooling (SIEM,
  vulnerability scanner), the dedicated vendor-access jump-host
Allowed Outbound: To every other zone, restricted to administrative
  protocols only (SSH 22, RDP 3389, SNMP, WMI), from specifically
  designated management source addresses, with MFA enforced on every
  session. This is the only zone permitted broad reach across the
  network, since it is the trusted administrative plane, itself gated
  by the strongest authentication control in the entire architecture.
Allowed Inbound: From the internet only via the FortiGate VPN, with MFA
  enforced; the VPN terminates into this zone specifically, not directly
  into the Server VLAN as it effectively does today.
```

```
Zone 5: Guest/IoT VLAN (VLAN 50) [NEW]
IP Range: 10.10.5.0/24
Systems: Visitor WiFi, the Greenfield Building Management System
  (previously unsegmented and flagged as an opaque, unaudited vendor
  relationship in 1x01, Task 5), personal devices under the Acceptable
  Use Policy's BYOD provisions
Allowed Outbound: To the internet only, filtered
Allowed Inbound: None from any internal zone. This zone has zero
  legitimate reason to initiate or receive traffic from the Server,
  Clinical Workstation, Medical Device, or Management zones, and is
  fully isolated from all of them.
```

```
Zone 6: Westside Site VLAN (VLAN 60)
IP Range: 10.10.10.0/24
Systems: Westside Clinic workstations and local devices, now behind the
  dedicated enterprise firewall already funded in this program's control
  selection (Task 7, Control 6), replacing the previous consumer-grade
  router
Allowed Outbound: To Server VLAN via an authenticated site-to-site VPN
  tunnel, restricted to the same application-port rules as the Clinical
  Workstation VLAN; to the internet, filtered
Allowed Inbound: From Management VLAN only, for remote administration
  and support
```

```
Zone 7: Corporate HQ VLAN (VLAN 70)
IP Range: 10.10.20.0/24
Systems: Administrative and non-clinical corporate staff workstations
Allowed Outbound: To Server VLAN, restricted specifically to billing
  and finance application ports; no route to clinical systems, since
  corporate administrative staff have no clinical need for EHR access;
  to the internet, filtered
Allowed Inbound: From Management VLAN only
```

---

## Part 2: Firewall Rules

```
Rule 1:  Clinical Workstation VLAN -> Server VLAN : 443/tcp (HTTPS) :
         ALLOW
         Purpose: Clinical staff reach the EHR application and patient
         portal through the standard web interface.

Rule 2:  Clinical Workstation VLAN -> Server VLAN : 5432/tcp
         (PostgreSQL) : DENY
         What this prevents: Any workstation directly querying the
         patient database, closing the exact exposure behind GAP-003
         and Finding 003 (1x02), the single most-referenced gap across
         this entire program.

Rule 3:  Medical Device VLAN -> Server VLAN (pacs-srv-01) : 4242,11112/
         tcp (DICOM) : ALLOW
         Purpose: Imaging devices and the MRI transmit studies to the
         PACS server, the legitimate clinical workflow this
         architecture must not break.

Rule 4:  Medical Device VLAN -> Internet : any/any : DENY
         What this prevents: No infusion pump, patient monitor, or the
         MRI workstation has any legitimate reason to reach the
         internet directly; this closes the path an already-compromised
         device (Finding 010, Finding 004) could otherwise use to reach
         external command-and-control infrastructure.

Rule 5:  Management VLAN -> Server VLAN : 22,3389/tcp (SSH, RDP) :
         ALLOW, restricted to designated management source addresses,
         MFA required
         Purpose: The only path for legitimate administrative access to
         production servers, consistent with the MFA control already
         selected for this risk (Task 11).

Rule 6:  Guest/IoT VLAN -> Server VLAN : any/any : DENY
         What this prevents: Visitor devices and the Greenfield Building
         Management System have zero legitimate reason to reach
         clinical or financial systems; this directly addresses the
         unaudited third-party device risk flagged in 1x01, Task 5.

Rule 7:  Server VLAN (ehr-srv-01) -> Medical Device VLAN : 2575/tcp
         (HL7) : ALLOW
         Purpose: Application-level clinical data exchange between the
         EHR and patient monitoring devices, the legitimate reverse
         direction of Rule 3's imaging workflow.

Rule 8:  Guest/IoT VLAN -> Medical Device VLAN : any/any : DENY
         What this prevents: A compromised guest or IoT device
         (including the building management system) reaching a patient
         care device directly; this is a deliberately separate rule
         from Rule 6, since a Server-VLAN-only deny rule would not by
         itself stop a Guest-to-Medical-Device path.

Rule 9:  Westside VLAN -> Server VLAN : 443/tcp : ALLOW, via
         authenticated site-to-site VPN tunnel only
         Purpose: Westside clinical staff reach the same EHR application
         Central staff use, through the new dedicated firewall (Task 7,
         Control 6) rather than the previous consumer router.

Rule 10: Any Zone -> Server VLAN (NAS-01, backup-srv-01) : any/any :
         DENY by default, with explicit exceptions limited to
         backup-srv-01 itself and the Management VLAN
         What this prevents: The broad, unrestricted reachability
         Finding 015 (1x02) documented for the backup infrastructure,
         directly hardening the exact asset BlackReef's own documented
         playbook targets before deploying ransomware (1x01, Task 2).
```

---

## Part 3: Kill Chain Impact

**Walking Kill Chain 1 (the ransomware campaign, "Operation Flatline") through this architecture, step by step:**

**Step 1-2 (Resource Development, Initial Access via spear phishing of the IT Director):** Not affected by this design. Segmentation is a network-layer control; it has no effect on email delivery or a user opening a malicious document. This step succeeds exactly as originally modeled, on a workstation now sitting in the Corporate HQ VLAN.

**Step 3 (Persistence via a disguised scheduled task):** Not affected. This happens locally on the already-compromised host, before any network boundary is crossed.

**Step 4 (Discovery, mapping the network):** **Meaningfully degraded.** Under this architecture, discovery commands run from the Corporate HQ VLAN reveal only what that zone can reach, the Server VLAN's specific allowed application ports, not the domain controller, the backup infrastructure, or the medical device fleet the way a flat network currently exposes them.

**Step 5 (Credential Access via Mimikatz/LSASS):** Not directly affected; local credential dumping on an already-compromised host does not require crossing a network boundary.

**Step 6 (Lateral Movement, pass-the-hash to the domain controller):** **Broken.** This is the decisive break point. Rule 5 restricts SSH and RDP to the Server VLAN to the Management VLAN only, from designated administrative source addresses, with MFA required. A pass-the-hash attempt originating from Corporate HQ has no path to ad-dc-01's administrative interfaces at all under this rule set.

**Step 7 (Collection and Exfiltration from the EHR and file server):** **Broken as a direct consequence of Step 6 failing.** Domain Admin access was never achieved, so the bulk file access this step depends on is unavailable; even a separate attempt to reach the Server VLAN through the Clinical Workstation VLAN would still be blocked at the database layer by Rule 2.

**Step 8 (Backup neutralization on NAS-01):** **Broken.** Rule 10 denies this exact path from any zone except backup-srv-01 and Management.

**Step 9 (Domain-wide ransomware deployment via malicious GPO, plus separate SSH-based encryption of Linux servers):** **Broken as a downstream consequence.** Without Domain Admin, no malicious GPO can be pushed; without a lateral path from Corporate HQ to billing-srv-01's SSH port, the separate Linux encryption path also fails.

**This architecture fully disrupts Kill Chain 1**, not by preventing the initial phishing compromise, which remains a human and email-security problem this design does not touch, but by converting what is currently a single foothold's path to total organizational compromise into a single foothold contained to one workstation in one zone.

**Estimating the impact across the top 5 kill chains from 1x01, stated honestly rather than optimistically:**

- **Kill Chain 1 (Ransomware): Fully disrupted**, as walked through above.
- **Kill Chain 2 (Opportunistic escalation from billing-srv-01 to the domain controller): Only partially disrupted**, and this limitation should be stated directly rather than glossed over. This design groups all production servers, including billing-srv-01 and ad-dc-01, into a single Server VLAN. Once an attacker compromises billing-srv-01 through its own vulnerability (unaffected by network segmentation, since that entry point is an application-layer flaw), lateral movement to ad-dc-01 remains possible within the same VLAN. Closing this fully requires a Phase 2 refinement, isolating the domain controller into its own dedicated zone, not part of this initial design.
- **Kill Chain 3 (Shadow IT pivot from an undocumented device on the server subnet): Only partially disrupted**, for the identical reason as Kill Chain 2, an undocumented device discovered inside the Server VLAN retains reach to other same-zone servers.
- **Kill Chain 4 (Business Email Compromise / wire transfer fraud): Not disrupted at all.** This kill chain has no network-layer dependency whatsoever; it is a social-engineering and financial-process risk that segmentation cannot address, consistent with this program's own prior finding (1x02, Task 6) that this chain was never tied to GAP-014.
- **Kill Chain 5 (Trusted Vendor Path): Partially disrupted.** Vendor access to ehr-srv-01 must remain functional for legitimate maintenance, so segmentation alone narrows but does not eliminate this path; full closure depends on pairing this architecture with the dedicated vendor jump-host control already selected for this risk (Task 11, RISK-009), routed through the Management VLAN with MFA and full session logging.

**Overall estimate: approximately 20% (1 of 5) of the kill chains built in this program are fully broken by this design alone; a further 60% (3 of 5) are meaningfully degraded but not fully closed, primarily because this initial design intentionally groups all servers into a single zone rather than pursuing full server-to-server micro-segmentation; the remaining 20% (Kill Chain 4) is unaffected, since it has no network-layer dependency at all.** This is a deliberately honest accounting rather than a claim that segmentation solves everything: it is the single highest-leverage architectural change available to MedDefense, and it is not, by itself, a complete defense.
